rule sig_20160517_dec2c8033674403eb233a0bb78e26711 {
  meta:
    description = "datamaliciousorder - file 20160517_dec2c8033674403eb233a0bb78e26711.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9745bb13925ab8ec61b8a6dc316cd3b12c64e11c25fd4ee888a038e2062766fd"

  strings:
    $s1 = "var jak='votixbapib3yryogxq jyryfzptjjlxhraq2janvqkxwdxbgkrtycqiyaog3mjsvibgz1xkqettduk=bvrq1\\'mmu1stzqw42cz3tulnfblwqiyvjjpfnc" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}