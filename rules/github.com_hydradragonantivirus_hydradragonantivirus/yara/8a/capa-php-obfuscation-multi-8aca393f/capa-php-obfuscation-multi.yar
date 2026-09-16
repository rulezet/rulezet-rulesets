rule capa_php_obfuscation_multi: WEBSHELL PROD {
  meta:
    description = "PHP obfuscation functions which have to be used multiple times, e.g. for each character"
    license     = "https://creativecommons.org/licenses/by-nc/4.0/"
    author      = "Arnim Rupp"
    date        = "2021/01/14"
    score       = 50

  strings:
    $o1  = "chr(" nocase wide ascii
    $o2  = "chr (" nocase wide ascii
        $o3  = "goto" fullword nocase wide ascii
    $o4  = "\\x9" wide ascii
    $o5  = "\\x3" wide ascii
        $o6  = "\\61" wide ascii
    $o7  = "\\44" wide ascii
    $o8  = "\\112" wide ascii
    $o9  = "\\120" wide ascii
    $fp1 = "$goto" wide ascii

  condition:
        not $fp1 and (
      (
        filesize < 20KB and
        (
          (#o1 + #o2) > 50 or
          #o3 > 10 or
          (#o4 + #o5 + #o6 + #o7 + #o8 + #o9) > 20
        )
      ) or (
        filesize < 200KB and
        (
          (#o1 + #o2) > 200 or
          #o3 > 30 or
          (#o4 + #o5 + #o6 + #o7 + #o8 + #o9) > 30
        )

      )
    )

}