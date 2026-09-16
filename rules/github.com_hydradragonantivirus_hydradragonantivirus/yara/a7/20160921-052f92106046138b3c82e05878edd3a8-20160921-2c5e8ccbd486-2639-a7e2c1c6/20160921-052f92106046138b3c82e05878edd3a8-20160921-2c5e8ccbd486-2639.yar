rule _20160921_052f92106046138b3c82e05878edd3a8_20160921_2c5e8ccbd486_2639 {
  meta:
    description = "datamaliciousorder - from files 20160921_052f92106046138b3c82e05878edd3a8.js, 20160921_2c5e8ccbd48636e7c625aae6ef954560.js, 20160921_4d30edc3a4e3226feee5b6289df9e399.js, 20160921_814859e3f9dab39a18edf940d1dd5650.js, 20160921_e26fc4dc1ccef911251bba0675c76ce0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4812ea00b657b288e9ad51c72fcf466179e82a552fa3278fa9a896cc053c9fdc"
    hash2       = "70244ca5fa124af09b1f94729567c09dbc52c05035ee7d20cbe87d35e1fe63c8"
    hash3       = "d28b5e72375443a9ef1a43fee185a0e5563672a0764eef4f58a90a27302162ea"
    hash4       = "c61c4f66b5cb5b5fa606db7d7b914cbb3fe4d8f1b8ae72ca6b16b707c575cfb0"
    hash5       = "f1074dcd9f3ae62af13634c9f88af0a235b2e315a2697fc222ce96bad51ca1a1"

  strings:
    $s1 = "),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){return \"MIl\";})(),(function fuck(" ascii
    $s2 = "fuck(){return \"Xw\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"Jg\";})(),(function fuck(){return \"Ar" ascii
    $s3 = "unction fuck(){return \"Xw\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){retur" ascii
    $s4 = "k(){return \"IPu\";})(),(function fuck(){return \"Wo\";})(),(function fuck(){return \"Ug\";})(),(function fuck(){return \"EHo\";" ascii
    $s5 = "urn \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"GJx\";})(),(function fuck(){return \"SUi\";})(),(" ascii
    $s6 = "Pu\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"Pc\";})(),(function fuck(){return \"KVh\";})(),(function" ascii
    $s7 = "k(){return \"Dc\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"IPu\"" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}