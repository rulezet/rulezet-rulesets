rule capa_php_new_long: WEBSHELL PROD {
  meta:
    description = "PHP tags, only <script language=\"php and <?php, no <?=. useful to avoid false positives in huge binary files and the old tag is dieing out anyway."
    license     = "https://creativecommons.org/licenses/by-nc/4.0/"
    author      = "Arnim Rupp"
    date        = "2021/01/14"

  strings:
        $new_php2  = "<?php" nocase wide ascii
    $new_php3  = "<script language=\"php" nocase wide ascii
    $php_short = "<?"

  condition:
    any of ($new_php*) or
    $php_short at 0
}