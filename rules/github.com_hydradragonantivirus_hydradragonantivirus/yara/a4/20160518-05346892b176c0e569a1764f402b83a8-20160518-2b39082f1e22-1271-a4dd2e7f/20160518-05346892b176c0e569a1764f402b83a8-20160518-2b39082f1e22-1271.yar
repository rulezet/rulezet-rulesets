rule _20160518_05346892b176c0e569a1764f402b83a8_20160518_2b39082f1e22_1271 {
  meta:
    description = "datamaliciousorder - from files 20160518_05346892b176c0e569a1764f402b83a8.js, 20160518_2b39082f1e22e1240fc69910ae751609.js, 20160518_5ff1282af13d28b7d8b692f4365ec50f.js, 20160519_d76374ff8967ae41097f193aae32f5ba.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "39fd3f82a97b629e807c5e1f44446a9941ad194bb793f756691ef3f9a0cd1bcb"
    hash2       = "e80fa74eef7dc7264f831816bc7203104c56fbe9d4ce0c2c757c2e327c02c677"
    hash3       = "eda3ee90800527738da21711fb96dc37400cdea72607bf5364cce3789bb75fd1"
    hash4       = "ae01d6d26d490dcca4d78e4eac6c1d03dd1799af19a60aa27009dc8bf75f3920"

  strings:
    $s1 = "solid1[CAD](getAttribute0 /* S  */, dingy, (true, false));" fullword ascii
    $s2 = "dot1 /* S  */= true;/* S  */" fullword ascii
    $s3 = "function sDiv2(){return newtonsCradle0 /* S  */;};" fullword ascii
    $s4 = "function doled(selectStart0){doled1[(\"3\", \"2\", \"R\")+ \"u\" + (\"1\", \"n\")](selectStart0, A8name /* S  */, A8name /* S  *" ascii
    $s5 = "newtonsCradle1 /* S  */ = \"start \"+picker+\"\\r\\nexit\"" fullword ascii

  condition:
    (uint16(0) == 0x6176 and (all of them)
    ) or (all of them)
}