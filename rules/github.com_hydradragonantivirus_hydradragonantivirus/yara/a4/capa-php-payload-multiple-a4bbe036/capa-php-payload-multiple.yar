rule capa_php_payload_multiple: WEBSHELL PROD {
  meta:
    description = "containing multiple PHP methods for executing OS commands or eval, in plain text"
    license     = "https://creativecommons.org/licenses/by-nc/4.0/"
    author      = "Arnim Rupp"
    date        = "2021/04/17"

  strings:
        $cmpayload1  = /\beval[\t ]*\([^)]/ nocase wide ascii
    $cmpayload2  = /\bexec[\t ]*\([^)]/ nocase wide ascii
    $cmpayload3  = /\bshell_exec[\t ]*\([^)]/ nocase wide ascii
    $cmpayload4  = /\bpassthru[\t ]*\([^)]/ nocase wide ascii
    $cmpayload5  = /\bsystem[\t ]*\([^)]/ nocase wide ascii
    $cmpayload6  = /\bpopen[\t ]*\([^)]/ nocase wide ascii
    $cmpayload7  = /\bproc_open[\t ]*\([^)]/ nocase wide ascii
    $cmpayload8  = /\bpcntl_exec[\t ]*\([^)]/ nocase wide ascii
    $cmpayload9  = /\bassert[\t ]*\([^)0]/ nocase wide ascii
    $cmpayload10 = /\bpreg_replace[\t ]*\([^\)]{1,100}\/e/ nocase wide ascii
    $cmpayload11 = /\bpreg_filter[\t ]*\([^\)]{1,100}\/e/ nocase wide ascii
    $cmpayload12 = /\bmb_ereg_replace[\t ]*\([^\)]{1,100}'e'/ nocase wide ascii
    $cmpayload20 = /\bcreate_function[\t ]*\([^)]/ nocase wide ascii
    $cmpayload21 = /\bReflectionFunction[\t ]*\([^)]/ nocase wide ascii

  condition:
    4 of ($cmpayload*)
}