rule capa_php_include: WEBSHELL PROD {
  meta:
    description = "PHP methods for including code from other files, in plain text"
    license     = "https://creativecommons.org/licenses/by-nc/4.0/"
    author      = "Arnim Rupp"
    date        = "2021/01/14"

  strings:
    $cinclude1 = /\binclude(_once)?[\t ]*[('"]/ nocase wide ascii
    $cinclude2 = /\brequire(_once)?[\t ]*[('"]/ nocase wide ascii

  condition:
    any of ($cinclude*)
}