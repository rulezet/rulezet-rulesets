rule sig_20160301_c9d8b7f40343ba75e4c2bfaaa6305a66 {
  meta:
    description = "datamaliciousorder - file 20160301_c9d8b7f40343ba75e4c2bfaaa6305a66.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6d700962927c61d9d1b5ea3396e1b4966e32ea326bc6567969429cfd1bc90369"

  strings:
    $s1 = "while(noseBlock[(\"\\u0061g\\u0065n\\u0074\", \"a\\u006do\\u0072\\u0070\\u0068\\u006fus\", \"r\\u0065\\u0061d\\u0079\\u0073t\\u0" ascii
    $s2 = "while(noseBlock[(\"\\u0061g\\u0065n\\u0074\", \"a\\u006do\\u0072\\u0070\\u0068\\u006fus\", \"r\\u0065\\u0061d\\u0079\\u0073t\\u0" ascii
    $s3 = "vacancyColony = ((3 * 23 * 3 & 5 * 7 * 5), this);" fullword ascii
    $s4 = "noseBlock[(\"\\u0073e\\u0073sio\\u006e\", function String.prototype.boatProduce() {" fullword ascii
    $s5 = "} catch(studentContract) {};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}