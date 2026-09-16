rule capa_php_write_file: WEBSHELL PROD {
  meta:
    description = "PHP file write"
    license     = "https://creativecommons.org/licenses/by-nc/4.0/"
    author      = "Arnim Rupp"
    date        = "2021/04/16"

  strings:
    $php_multi_write1 = "fopen(" wide ascii
    $php_multi_write2 = "fwrite(" wide ascii
    $php_write1       = "move_uploaded_file" fullword wide ascii

  condition:
    any of ($php_write*) or
    all of ($php_multi_write*)
}