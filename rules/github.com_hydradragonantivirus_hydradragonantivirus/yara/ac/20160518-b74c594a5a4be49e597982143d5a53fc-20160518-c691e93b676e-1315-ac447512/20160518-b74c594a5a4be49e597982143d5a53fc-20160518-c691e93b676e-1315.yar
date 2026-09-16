rule _20160518_b74c594a5a4be49e597982143d5a53fc_20160518_c691e93b676e_1315 {
  meta:
    description = "datamaliciousorder - from files 20160518_b74c594a5a4be49e597982143d5a53fc.js, 20160518_c691e93b676e4aa902e2bb7d00b2fff9.js, 20160518_d357c0dbc6d5c9e2129add5caad6b8ee.js, 20160518_d57f93cb586230240d9013e317916ada.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cdc84bf792e10aa64e3d75d0922a4d950aa3bc938546affb66b20e8a2d577eaa"
    hash2       = "54023e6b7de2d0cbd393794b78bb3696898cad272347fe0a3c4c108fbf658e54"
    hash3       = "4532ebc6f43eed2d4e368dd2beb424573712106c68da04c6abc96b4f3b18d576"
    hash4       = "72b42636ec7a0c8957fd52e9004e6407a3322a1edc1a0f2a01986fdf9f659f1d"

  strings:
    $s1 = "solid1[CAD](getAttribute0 /* q  */, dingy, (true, false));" fullword ascii
    $s2 = "function doled(selectStart0){doled1[(\"3\", \"2\", \"R\")+ \"u\" + (\"1\", \"n\")](selectStart0, A8name /* q  */, A8name /* q  *" ascii
    $s3 = "dot1 /* q  */= true;/* q  */" fullword ascii
    $s4 = "newtonsCradle1 /* q  */ = \"start \"+picker+\"\\r\\nexit\"" fullword ascii
    $s5 = "function sDiv2(){return newtonsCradle0 /* q  */;};" fullword ascii

  condition:
    (uint16(0) == 0x6176 and (all of them)
    ) or (all of them)
}