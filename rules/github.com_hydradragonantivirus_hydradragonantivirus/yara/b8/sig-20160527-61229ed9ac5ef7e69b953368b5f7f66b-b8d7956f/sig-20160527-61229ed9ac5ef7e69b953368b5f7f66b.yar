rule sig_20160527_61229ed9ac5ef7e69b953368b5f7f66b {
  meta:
    description = "datamaliciousorder - file 20160527_61229ed9ac5ef7e69b953368b5f7f66b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "74f5d8380a3c3e821b50124cf90518bde26dc2ed5d9cd8e74ac4208048f9cbea"

  strings:
    $s1 = "    x = new Array(); for (i=0;i<atMMDKt6.length;i++)if(i%2==0)x.push(atMMDKt6[\"charAt\"](i));" fullword ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}