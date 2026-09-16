rule _20160518_2d90ec2588af35d77db75305a07f5f1b_20160518_366c96bfd887_1289 {
  meta:
    description = "datamaliciousorder - from files 20160518_2d90ec2588af35d77db75305a07f5f1b.js, 20160518_366c96bfd887e0bb0b842a3f7b279772.js, 20160518_6602485d0927a844920e0bd40251696d.js, 20160518_9ed9721281e9f3fd76e36130a83b4451.js, 20160518_f46f5f9222aa726d0d5e68bde51f2d5e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0f3980b5d1078adf3200569fd9a272a9a71f6270dadd578cbfd34910e0b0c86a"
    hash2       = "5a596dd447af11033edc137a7a29ad580fe66a65ac040bef2a90bd014ac11202"
    hash3       = "57f7a4454953ee45437d9effb626e878120bddfcbe4da8c0d11526722723a07e"
    hash4       = "075a840ee4295e112645ca8f85732ceb3d352da10a96488dc9a5da0161288126"
    hash5       = "c24e65409a086535b3ac59d17143ea02bc4dfd8601f0e13b1e44180448d87b9f"

  strings:
    $s1 = "solid1[CAD](getAttribute0 /* g  */, dingy, (true, false));" fullword ascii
    $s2 = "function sDiv2(){return newtonsCradle0 /* g  */;};" fullword ascii
    $s3 = "newtonsCradle1 /* g  */ = \"start \"+picker+\"\\r\\nexit\"" fullword ascii
    $s4 = "dot1 /* g  */= true;/* g  */" fullword ascii
    $s5 = "function doled(selectStart0){doled1[(\"3\", \"2\", \"R\")+ \"u\" + (\"1\", \"n\")](selectStart0, A8name /* g  */, A8name /* g  *" ascii

  condition:
    (uint16(0) == 0x6176 and (all of them)
    ) or (all of them)
}