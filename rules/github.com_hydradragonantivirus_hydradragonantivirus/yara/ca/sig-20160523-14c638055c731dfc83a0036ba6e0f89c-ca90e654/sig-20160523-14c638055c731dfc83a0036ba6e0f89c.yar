rule sig_20160523_14c638055c731dfc83a0036ba6e0f89c {
  meta:
    description = "datamaliciousorder - file 20160523_14c638055c731dfc83a0036ba6e0f89c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d486b64660a4d6976a229df0cd0df863db3a6c3ed6ba4815f0bcf7480a788239"

  strings:
    $s1 = "verse().join('');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}