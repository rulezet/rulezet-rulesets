rule sig_20151230_524c5fbdc847f88facc6d2cea1dbe308 {
  meta:
    description = "datamaliciousorder - file 20151230_524c5fbdc847f88facc6d2cea1dbe308.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "751dbd56ee72a3126b37fb656a5f077af4453d8982105c19c303cd0fb451ef2e"

  strings:
    $s1 = "print(yuqqhjrzm);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}