rule _20160518_058b8035a61c75bb83b247018abced2a_20160518_0e26432006dc_1272 {
  meta:
    description = "datamaliciousorder - from files 20160518_058b8035a61c75bb83b247018abced2a.js, 20160518_0e26432006dc9fd2be3dc80423de9741.js, 20160518_3e48ed469f82f263f75bb55a2720a983.js, 20160518_68521913210d9056410ae452f354ebbb.js, 20160518_c935395310a75fdf534c0150fdbf567c.js, 20160518_d9e95bb9f5b91d093b4d15634f861d11.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8080b7d0027faa6f19f7f21d9f8ba16c099a2a057f4dddd81833a595b1cc8739"
    hash2       = "51647006a58c6323c117fe3b04ac26b4c8ab6431aa720cc8e0d7ccccfeca3380"
    hash3       = "b058a9ef9171498bec62961d86dee341fdf2f55b4b3101894bbcaa50ba1cdd4d"
    hash4       = "ce47c3930f0821a3954bc2b25e0055d5909b3277e7ab07cf0905e9c0f2f87db1"
    hash5       = "58b59c0313a80dacad12b7ccdf8e1491281f7c49ad2a2d68dc1c4044a8edcee9"
    hash6       = "0bd188f7844bfc8bbf48122590f290a513c5e7587100d890d529941d5dbb5b5c"

  strings:
    $s1 = "solid1[CAD](getAttribute0 /* F  */, dingy, (true, false));" fullword ascii
    $s2 = "newtonsCradle1 /* F  */ = \"start \"+picker+\"\\r\\nexit\"" fullword ascii
    $s3 = "function doled(selectStart0){doled1[(\"3\", \"2\", \"R\")+ \"u\" + (\"1\", \"n\")](selectStart0, A8name /* F  */, A8name /* F  *" ascii
    $s4 = "dot1 /* F  */= true;/* F  */" fullword ascii
    $s5 = "function sDiv2(){return newtonsCradle0 /* F  */;};" fullword ascii

  condition:
    (uint16(0) == 0x6176 and (all of them)
    ) or (all of them)
}