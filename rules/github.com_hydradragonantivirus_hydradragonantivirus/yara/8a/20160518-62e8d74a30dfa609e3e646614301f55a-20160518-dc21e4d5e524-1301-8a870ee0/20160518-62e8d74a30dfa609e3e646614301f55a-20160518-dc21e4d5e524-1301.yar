rule _20160518_62e8d74a30dfa609e3e646614301f55a_20160518_dc21e4d5e524_1301 {
  meta:
    description = "datamaliciousorder - from files 20160518_62e8d74a30dfa609e3e646614301f55a.js, 20160518_dc21e4d5e524eb0add7fa85aaaa5d5f0.js, 20160519_a79163636b3dc8ebdcdd18591352da35.js, 20160519_ff58f37070ff07e25fdd1040d6a6e468.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ea73e9a13889af1242c32f4365c2c3a3f14c1f50e9856cf7d4dff25ff208bf85"
    hash2       = "13db6ffb6c68183c4c6bd2343ed35186ce15e2b7fbd8ff695b9e5926c7a945da"
    hash3       = "ea573698412c9e49bb0d5bbd61128f218a7a2c5701d2d643c57a431bd302eab3"
    hash4       = "b8b0508c2402c0fe2b827139767f66b1a0eccf07e1ff7c3c449158805047d826"

  strings:
    $s1 = "solid1[CAD](getAttribute0 /* D  */, dingy, (true, false));" fullword ascii
    $s2 = "function sDiv2(){return newtonsCradle0 /* D  */;};" fullword ascii
    $s3 = "dot1 /* D  */= true;/* D  */" fullword ascii
    $s4 = "newtonsCradle1 /* D  */ = \"start \"+picker+\"\\r\\nexit\"" fullword ascii
    $s5 = "function doled(selectStart0){doled1[(\"3\", \"2\", \"R\")+ \"u\" + (\"1\", \"n\")](selectStart0, A8name /* D  */, A8name /* D  *" ascii

  condition:
    (uint16(0) == 0x6176 and (all of them)
    ) or (all of them)
}