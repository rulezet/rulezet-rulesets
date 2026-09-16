rule _20160518_03e3da78d37a16708d379c0ec9f2448b_20160518_9e603987e8bc_1270 {
  meta:
    description = "datamaliciousorder - from files 20160518_03e3da78d37a16708d379c0ec9f2448b.js, 20160518_9e603987e8bcc05e7ce31cbca89689f8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2ed89e6f7209558ab3318904011c99f9d2489fe2b3b4b9f3162f66bd3257c23e"
    hash2       = "7591ab5ef7c6660f32fbfb9804dbb387b9e247e3317828a699123e3fb203d4e7"

  strings:
    $s1 = "solid1[CAD](getAttribute0 /* V  */, dingy, (true, false));" fullword ascii
    $s2 = "dot1 /* V  */= true;/* V  */" fullword ascii
    $s3 = "function sDiv2(){return newtonsCradle0 /* V  */;};" fullword ascii
    $s4 = "function doled(selectStart0){doled1[(\"3\", \"2\", \"R\")+ \"u\" + (\"1\", \"n\")](selectStart0, A8name /* V  */, A8name /* V  *" ascii
    $s5 = "newtonsCradle1 /* V  */ = \"start \"+picker+\"\\r\\nexit\"" fullword ascii

  condition:
    (uint16(0) == 0x6176 and (all of them)
    ) or (all of them)
}