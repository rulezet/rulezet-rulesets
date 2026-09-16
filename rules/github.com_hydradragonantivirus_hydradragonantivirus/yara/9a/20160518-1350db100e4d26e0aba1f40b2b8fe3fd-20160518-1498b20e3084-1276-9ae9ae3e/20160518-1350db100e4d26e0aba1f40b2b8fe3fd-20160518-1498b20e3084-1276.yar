rule _20160518_1350db100e4d26e0aba1f40b2b8fe3fd_20160518_1498b20e3084_1276 {
  meta:
    description = "datamaliciousorder - from files 20160518_1350db100e4d26e0aba1f40b2b8fe3fd.js, 20160518_1498b20e3084c1b1f9347a5ea7ad508d.js, 20160518_7b334214a4be7766ca1d4577d69dfe00.js, 20160518_90b69adcc8c0b3c1b55396d0d5c66158.js, 20160518_f9597f90af7c3d4b4dc0a2a578db0996.js, 20160518_ff6ff9f8dc2aade12db72ce5e0cb4d62.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7e2fc4a2288f537b8059b50fbb7bc752adf35f4b698ae2f7669a83c0ab1aa4e3"
    hash2       = "8578003f8774551af3f1558500f3d31bb7d5003cae66ec7dc5179d28dfef66c5"
    hash3       = "8bad1fced4ecb0021dbf75f3fddcb4b982b08bc6f8f4acd7e1c2b77229389daa"
    hash4       = "bd2282a4deee74f8f9626d02694a021c5e024f496ae3ca1ee27c2c59f5b61dc5"
    hash5       = "db9bb2c47b200752b1459c6b8654fdc04dac573d0ae57e9f50f871716ba2f558"
    hash6       = "78357c928dbfa657f377e82664dfaec41714acacbb1b0b4fa3f63fc3b970721f"

  strings:
    $s1 = "solid1[CAD](getAttribute0 /* p  */, dingy, (true, false));" fullword ascii
    $s2 = "dot1 /* p  */= true;/* p  */" fullword ascii
    $s3 = "newtonsCradle1 /* p  */ = \"start \"+picker+\"\\r\\nexit\"" fullword ascii
    $s4 = "function doled(selectStart0){doled1[(\"3\", \"2\", \"R\")+ \"u\" + (\"1\", \"n\")](selectStart0, A8name /* p  */, A8name /* p  *" ascii
    $s5 = "function sDiv2(){return newtonsCradle0 /* p  */;};" fullword ascii

  condition:
    (uint16(0) == 0x6176 and (all of them)
    ) or (all of them)
}