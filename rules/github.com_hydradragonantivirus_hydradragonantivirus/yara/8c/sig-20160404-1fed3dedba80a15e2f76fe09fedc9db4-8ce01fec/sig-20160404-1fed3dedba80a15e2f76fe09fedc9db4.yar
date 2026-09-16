rule sig_20160404_1fed3dedba80a15e2f76fe09fedc9db4 {
  meta:
    description = "datamaliciousorder - file 20160404_1fed3dedba80a15e2f76fe09fedc9db4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e112258be65e62cea6f3573fdeabd0a14676663d2a148ba326ea3282d4c97d07"

  strings:
    $s1 = "print (leri);" fullword ascii
    $s2 = "//deras = this;" fullword ascii
    $s3 = "} catch(x) {" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}