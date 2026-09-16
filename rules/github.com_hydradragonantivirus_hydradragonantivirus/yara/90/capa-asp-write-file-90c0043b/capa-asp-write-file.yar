rule capa_asp_write_file: WEBSHELL PROD {
  meta:
    description = "ASP file write"
    license     = "https://creativecommons.org/licenses/by-nc/4.0/"
    author      = "Arnim Rupp"
    date        = "2021/04/08"

  strings:
        $asp_always_write1  = /\.write/ nocase wide ascii
    $asp_always_write2  = /\.swrite/ nocase wide ascii
        $asp_write_way_one2 = "SaveToFile" fullword nocase wide ascii
    $asp_write_way_one3 = "CREAtEtExtFiLE" fullword nocase wide ascii
    $asp_cr_write1      = "CreateObject(" fullword nocase wide ascii
    $asp_cr_write2      = "CreateObject (" fullword nocase wide ascii
    $asp_streamwriter1  = "streamwriter" fullword nocase wide ascii
    $asp_streamwriter2  = "filestream" fullword nocase wide ascii

  condition:
    any of ($asp_always_write*) and
    (
      any of ($asp_write_way_one*) and
      any of ($asp_cr_write*)
    ) or (
      any of ($asp_streamwriter*)
    )
}