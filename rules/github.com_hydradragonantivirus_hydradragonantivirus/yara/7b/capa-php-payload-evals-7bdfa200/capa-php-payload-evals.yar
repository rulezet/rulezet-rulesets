rule capa_php_payload_evals: WEBSHELL PROD {
  meta:
    description = "PHP methods for any kind of eval"
    license     = "https://creativecommons.org/licenses/by-nc/4.0/"
    author      = "Arnim Rupp"
    date        = "2021/01/14"

  strings:
        $cpayload1  = /\beval[\t ]*\([^)]/ nocase wide ascii
    $cpayload9  = /\bassert[\t ]*\([^)0]/ nocase wide ascii
    $cpayload10 = /\bpreg_replace[\t ]*\(.{1,100}\/[ismxADSUXju]{0,11}(e|\\x65)/ nocase wide ascii
    $cpayload12 = /\bmb_ereg_replace[\t ]*\([^\)]{1,100}'e'/ nocase wide ascii
    $cpayload13 = /\bmb_eregi_replace[\t ]*\([^\)]{1,100}'e'/ nocase wide ascii
    $cpayload20 = /\bcreate_function[\t ]*\([^)]/ nocase wide ascii
    $cpayload21 = /\bReflectionFunction[\t ]*\([^)]/ nocase wide ascii

    $m_cpayload_preg_filter1 = /\bpreg_filter[\t ]*\([^\)]/ nocase wide ascii
    $m_cpayload_preg_filter2 = "'|.*|e'" nocase wide ascii
  
  condition:
    any of ($cpayload*) or
    all of ($m_cpayload_preg_filter*)
}