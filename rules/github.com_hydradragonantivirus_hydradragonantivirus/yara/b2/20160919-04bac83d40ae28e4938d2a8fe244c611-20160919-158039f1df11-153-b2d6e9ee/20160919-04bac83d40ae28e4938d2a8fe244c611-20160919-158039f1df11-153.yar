rule _20160919_04bac83d40ae28e4938d2a8fe244c611_20160919_158039f1df11_153 {
  meta:
    description = "datamaliciousorder - from files 20160919_04bac83d40ae28e4938d2a8fe244c611.js, 20160919_158039f1df11dcf800563dee244ced9a.js, 20160919_27a0bd7235a221c6eeede9b2595935b3.js, 20160919_2bb2b5c0edaa899a7ccd97343fa4d1d3.js, 20160919_34293f55ed99f306841a5b91c9124de9.js, 20160919_5b08a2e9ece93a7940a30277e9c25a72.js, 20160919_5ee1abf0bedc2bf2a6e98b3e4b1a0913.js, 20160919_6b9c45444266d228b600f9c0b94c56cc.js, 20160919_6d4f3f0b74ca1a484510c096897d2478.js, 20160919_73973fc53d95c20f1db8c3a1a4942436.js, 20160919_794a0554f4e66351b539be6b775fb472.js, 20160919_81712cd1ad64688396a2ad453e946cc0.js, 20160919_8c8d57e2604859add6ddde3baacd3cf1.js, 20160919_8d98640fdf98b7eba650c33057d0b6a8.js, 20160919_aa082d9e3e132dc721f5c0dfe5cb9525.js, 20160919_be782342e371d5175f08659877353586.js, 20160919_ce631c82b8d81871646ea4da15788ce8.js, 20160919_cf6914cb3e5d574d060bfd144a837853.js, 20160919_d6b2fd0f1146dca6c03986c8d8499e69.js, 20160919_db003e0ae668c1137834ad6d10d1c18a.js, 20160919_def39a44663a401a845bf7256690d758.js, 20160919_edb58356df73f55d8be9d98ebbe239a9.js, 20160919_f8f64650da491a1bb4befc8f5d71e389.js, 20160919_f97e0353e073f5d6b482da14c5e7032f.js, 20160919_fa708a33b77b67e6f879282827753177.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d270dc520728b5589af3dd0523f407220f47448dda7c2680f4dbfe338701e409"
    hash2       = "c9594cae4ef65fddba46957a0f01493f0e9d0f8720709ffc0f030a9075113ce7"
    hash3       = "8525726f6fb24d36d5eef2ffd189e1aa37001eebf19bcda559fc8c3e6f702c7d"
    hash4       = "cc355e022e42af02ceb2baea3f128ebe66ac25e89fce904c3c4aeab5f426ae9e"
    hash5       = "815417151886174e59ac4f81caf122db3db8f4f3812094ee8a800ec4bae683cd"
    hash6       = "684c00d98844e396ef6d3a70246ee661084ac888499637b8a774c64e99065b78"
    hash7       = "352bcfe61cfc3d09075f263306b782b9e781f946ccf51a95867f969b75094198"
    hash8       = "7476216adb7596b587e6a276ceda9d69356057bb2129b83502ca34da4b83c1ba"
    hash9       = "bb12e5393ebd03969d803a40b8a6740e04dd69c0de9b9dbc349b0efd21bab34f"
    hash10      = "2a5203f4d658441d807eb89908e7638bd208bcc01fca3fc6dfdd49dbe4a715bb"
    hash11      = "4036df6bb80f90131fa28ed6319b1ab4d3ca220ef1beab6d3886ea78f52741cf"
    hash12      = "ddf33b5630b5f8e76859d2a8b4f92ebdf14fbc897865929ff18447bd5bbb2273"
    hash13      = "e72bc0e6bda307c2667b7c8aef90daa3f91951e490507c6529b26533558f2d17"
    hash14      = "992461e9f544ff6c9a055dbd1aa13453e1e6fb45e8dec21cd3d53ad7d2778c07"
    hash15      = "1aab9f9ba93e7a83204bb19ae1f421fff5ce300ab5f3d18e30090387bad1f83d"
    hash16      = "382bc5c0e9d1c33712349999448d05188bf6034da01ade4454ef352fc93a6cec"
    hash17      = "34e2a4d21335111fbbe2d4eba0b4f7e6966e8141ea52df8253ba014fad6ec75c"
    hash18      = "b93864b8ac1bee47c9cfa8c786fbe3132450b5e088ba65892e2c873c9e82981c"
    hash19      = "bb5379b7891a19c2ee33d3fc220f4b949b4b74b8ca46d2cd7b36713bd046dcef"
    hash20      = "c16abd8306dc8e3ed82f7ad118a5e962dba266e60ee7529939800481f23f52e0"
    hash21      = "4b18a3ceb5a3afb49c9eb2f0b5ef992f80a933505ad8e7d35ecfc2fe8619aec3"
    hash22      = "b55f2862caa073d13111e15b34fd72df044da323d6b7083fc3860152393bbb11"
    hash23      = "0b5cbc86fb6fa004a88c46a684a2848308c6fc7619defee8ff8f98d3b34cd994"
    hash24      = "46e2fe8ca8ddc6da125145490a5d97e55229d81402cecc899b6050b8dc6ccd99"
    hash25      = "29e94b5eb64af513d6eed679748fbe2d66b6c97ab778e40320a3a7ad67a5a566"

  strings:
    $s1  = ", [4, (function avast(){return \"6\";})()]], \"SIk\": [3, [4, (function avast(){return \"8\";})()]], \"Xh\": [3, [4, (function a" ascii
    $s2  = "n \"\\x4f\";})()]], \"Lp\": [3, [4, (function avast(){return \"2\";})()]], \"RAp\": [3, [4, (function avast(){return \"\\x4a\";}" ascii
    $s3  = "eturn \"\\x44\";})()]], \"XZg\": [3, [4, (function avast(){return \"\\x45\";})()]], \"VIs\": [3, [4, (function avast(){return \"" ascii
    $s4  = "], \"Eb\": [3, [4, (function avast(){return \"\\x47\";})()]], \"JWk\": [3, [4, (function avast(){return \"\\x40\";})()]], \"ITe" ascii
    $s5  = ", \"Qq\": [3, [4, (function avast(){return \"\\x0d\";})()]], \"Jb\": [3, [4, (function avast(){return \"\\x09\";})()]], \"Ih\": " ascii
    $s6  = " [3, [4, (function avast(){return \"\\x4b\";})()]], \"WTd\": [3, [4, (function avast(){return \"\\x4c\";})()]], \"Yn\": [3, [4, " ascii
    $s7  = "ction avast(){return \"\\x4d\";})()]], \"SZv\": [3, [4, (function avast(){return \"\\x4e\";})()]], \"Lz\": [3, [4, (function ava" ascii
    $s8  = "st(){return \"0\";})()]], \"Ru\": [3, [4, (function avast(){return \"4\";})()]], \"FGm\": [3, [4, (function avast(){return \"\\x" ascii
    $s9  = "avast(){return \"\\x3a\";})()]], \"Ph\": [3, [4, (function avast(){return \"\\x3c\";})()]], \"JKw\": [3, [4, (function avast(){r" ascii
    $s10 = "function avast(){return \"\\x41\";})()]], \"NAx\": [3, [4, (function avast(){return \"\\x42\";})()]], \"CRm\": [3, [4, (function" ascii
    $s11 = " [4, (function avast(){return \"\\x73\";})()]], \"ILs\": [3, [4, (function avast(){return \"\\x72\";})()]], \"GBs\": [3, [4, (fu" ascii
    $s12 = "var QDu = {\"NPd\": [3, [4, (function avast(){return \"\\x6b\";})()]], \"Dp\": [3, [4, (function avast(){return \"\\x79\";})()]]" ascii
    $s13 = "b\";})()]], \"Pc\": [3, [4, (function avast(){return \"\\x3e\";})()]], \"Uj\": [3, [4, (function avast(){return \"\\x3d\";})()]]" ascii

  condition:
    (uint16(0) == 0x0a0a and (8 of them)
    ) or (all of them)
}