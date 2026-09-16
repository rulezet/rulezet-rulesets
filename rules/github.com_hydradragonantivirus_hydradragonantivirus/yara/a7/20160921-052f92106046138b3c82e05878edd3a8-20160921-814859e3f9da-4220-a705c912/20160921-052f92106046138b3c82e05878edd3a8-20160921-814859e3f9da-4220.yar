rule _20160921_052f92106046138b3c82e05878edd3a8_20160921_814859e3f9da_4220 {
  meta:
    description = "datamaliciousorder - from files 20160921_052f92106046138b3c82e05878edd3a8.js, 20160921_814859e3f9dab39a18edf940d1dd5650.js, 20160921_af22e174703ebae0fa1368fd471dba37.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4812ea00b657b288e9ad51c72fcf466179e82a552fa3278fa9a896cc053c9fdc"
    hash2       = "c61c4f66b5cb5b5fa606db7d7b914cbb3fe4d8f1b8ae72ca6b16b707c575cfb0"
    hash3       = "24c1540f49c4fe83a182058f70751619567afa9e8884c1dee7ae13e5fad14a59"

  strings:
    $s1 = "eturn \"ZLd\";})(),(function fuck(){return \"Ug\";})(),(function fuck(){return \"UXf\";})(),(function fuck(){return \"IPu\";})()" ascii
    $s2 = " \"FJs\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"XFd\";})(),(fu" ascii
    $s3 = "rn \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"KVh\";})(),(" ascii
    $s4 = " \"DRx\";})(),(function fuck(){return \"Vf\";})(),(function fuck(){return \"FJs\";})(),(function fuck(){return \"DRx\";})(),(fun" ascii
    $s5 = ",(function fuck(){return \"Hs\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}