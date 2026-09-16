rule webshell_php_in_htaccess: WEBSHELL PROD {
  meta:
    description = "Use Apache .htaccess to execute php code inside .htaccess"
    license     = "https://creativecommons.org/licenses/by-nc/4.0/"
    author      = "Arnim Rupp"
    date        = "2021/01/07"
    hash        = "c026d4512a32d93899d486c6f11d1e13b058a713"

  strings:
    $hta = "AddType application/x-httpd-php .htaccess" wide ascii

  condition:
    filesize < 100KB and
    $hta
}