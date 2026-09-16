rule _20160518_6d1bbba2a79a1e95fb354ccf6d1ff887_20160518_8d96d34e5482_1306 {
  meta:
    description = "datamaliciousorder - from files 20160518_6d1bbba2a79a1e95fb354ccf6d1ff887.js, 20160518_8d96d34e54820f52d4e3af0cae67cefd.js, 20160518_c20c8b97c5f0022a1076974a01c60deb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3eb2acdeebf377e951006a058f8c08502654d85eccae9d7badf19dcb51ac0301"
    hash2       = "d03ef95ad0d1db74a6caf0de059873ebac1028cbfc29b7b91e2a29bec9586541"
    hash3       = "21e0b41bd3e0d53c25e261d0202d1cb4c7e085861fba6be752278b8ea52ff329"

  strings:
    $s1 = "solid1[CAD](getAttribute0 /* m  */, dingy, (true, false));" fullword ascii
    $s2 = "newtonsCradle1 /* m  */ = \"start \"+picker+\"\\r\\nexit\"" fullword ascii
    $s3 = "function doled(selectStart0){doled1[(\"3\", \"2\", \"R\")+ \"u\" + (\"1\", \"n\")](selectStart0, A8name /* m  */, A8name /* m  *" ascii
    $s4 = "function sDiv2(){return newtonsCradle0 /* m  */;};" fullword ascii
    $s5 = "dot1 /* m  */= true;/* m  */" fullword ascii

  condition:
    (uint16(0) == 0x6176 and (all of them)
    ) or (all of them)
}