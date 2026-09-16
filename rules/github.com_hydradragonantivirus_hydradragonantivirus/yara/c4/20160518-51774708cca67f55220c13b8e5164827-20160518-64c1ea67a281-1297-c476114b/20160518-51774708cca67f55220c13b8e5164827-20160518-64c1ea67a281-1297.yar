rule _20160518_51774708cca67f55220c13b8e5164827_20160518_64c1ea67a281_1297 {
  meta:
    description = "datamaliciousorder - from files 20160518_51774708cca67f55220c13b8e5164827.js, 20160518_64c1ea67a28155e6eb2967d9f2f1b7f2.js, 20160519_a9c3ffd34751ceff56c6f27db90f0a65.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "200a1c7e23a17c57b2bfccf5bebb182681d8b0a9da3ca32d06d834d03900299f"
    hash2       = "4fcf28fd411e046dcbdb8c4b3bebf299aedad6a258813b922c8a2812cd16ef2f"
    hash3       = "cf08b0322ce364a62deb11ae08e15e1f7c43dfe21eb6882feecd3b045ae31792"

  strings:
    $s1 = "solid1[CAD](getAttribute0 /* Z  */, dingy, (true, false));" fullword ascii
    $s2 = "function sDiv2(){return newtonsCradle0 /* Z  */;};" fullword ascii
    $s3 = "dot1 /* Z  */= true;/* Z  */" fullword ascii
    $s4 = "newtonsCradle1 /* Z  */ = \"start \"+picker+\"\\r\\nexit\"" fullword ascii
    $s5 = "function doled(selectStart0){doled1[(\"3\", \"2\", \"R\")+ \"u\" + (\"1\", \"n\")](selectStart0, A8name /* Z  */, A8name /* Z  *" ascii

  condition:
    (uint16(0) == 0x6176 and (all of them)
    ) or (all of them)
}