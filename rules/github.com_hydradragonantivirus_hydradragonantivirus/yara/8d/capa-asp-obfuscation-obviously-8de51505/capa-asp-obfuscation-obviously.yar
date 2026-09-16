rule capa_asp_obfuscation_obviously: WEBSHELL PROD {
  meta:
    description = "ASP obfuscation functions which are very obvious because they don't have a legitimate use (I can imageing ;)"
    license     = "https://creativecommons.org/licenses/by-nc/4.0/"
    author      = "Arnim Rupp"
    date        = "2021/03/14"
    score       = 60

  strings:
    $oo1 = /\w\"&\"\w/ wide ascii
    $oo2 = "*/\").Replace(\"/*" wide ascii

  condition:
    (
      filesize < 100KB and
      (
        (#oo1) > 2 or
        $oo2
      )
    ) or (
      filesize < 25KB and
      (
        (#oo1) > 1
      )
    ) or (
      filesize < 1KB and
      (
        (#oo1) > 0
      )
    )
}