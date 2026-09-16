rule sig_20160517_1feb1a9ca312772684c8233b9da5683c {
  meta:
    description = "datamaliciousorder - file 20160517_1feb1a9ca312772684c8233b9da5683c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "74478c5663b846a1ee3efd26a0d47864bf3343073379622c5b6e602b26de29d8"

  strings:
    $s1 = "var d3qc3v='vag2jsafceh2rgaxsu yrt1nekm2nasv3213sehjwucbw1kdagqizjhtcb1dlyyuumrtcp1cqkunbr=whnjv\\'zlmektylqblcaxjssneryprighmsm" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}