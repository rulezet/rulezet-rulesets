rule sig_20160526_84959c53875e7a2c13ce312d09721b01 {
  meta:
    description = "datamaliciousorder - file 20160526_84959c53875e7a2c13ce312d09721b01.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6a7508da74a54649c2b355307007cdafb32cd48bffd7e56c962b5ceb738f7858"

  strings:
    $s1 = "LACY rav\\n\\r;\"Besn\" = 9iBPM rav\\n\\r;\"do\" = yYND rav\\n\\r;\"y\" = bMPY rav\\n\\r;\"tisop\" = 0vWLJHDL rav\\n\\r;\"oi\" =" ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}