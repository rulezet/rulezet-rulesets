rule _20160518_4d58cd085cff7e7f0124c6410c300868_20160518_56a411089f8a_1295 {
  meta:
    description = "datamaliciousorder - from files 20160518_4d58cd085cff7e7f0124c6410c300868.js, 20160518_56a411089f8a0531752882ff90fc153f.js, 20160518_6509cd6dedfe6381e8bca38b3c836231.js, 20160518_c20df48e33e408398b30381e396e0ed3.js, 20160518_dd313890a7ded9c3815b3303ca04b445.js, 20160518_fa4ae613b62cf587189596d2b143b0a0.js, 20160519_d12f81b788c90e6e780f68f7ea37d67d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7fda31c60f8fac14595dcf34d6cc730e67976ede748334b05ec0eb4c6e3c8850"
    hash2       = "c0cc1883ac5239fd3264d74e1c6fb119d4eb99c3ed6e38096a84e29735b78fc1"
    hash3       = "689a124f5bbd5b857db5d456f535a96a686d02f0b1641badf1c7b8519bf1b915"
    hash4       = "fb981efbcc5dd1adb2ac2c690822352c9d6d6b5eac013c104e1336c3defe94a4"
    hash5       = "d143a856249547ec29b6ba6a0e452cf02a0bdec6eb2cab5d9c103840bc80f811"
    hash6       = "58b3a2bbadcc4c391fab8a28e5f5acadc08f09d2ff04d1899cbbf59ce86001e3"
    hash7       = "b991e4e32cdd94826fd755c055dd08488df2e718d60d3b51d979c7801d130c88"

  strings:
    $s1 = "solid1[CAD](getAttribute0 /* H  */, dingy, (true, false));" fullword ascii
    $s2 = "function doled(selectStart0){doled1[(\"3\", \"2\", \"R\")+ \"u\" + (\"1\", \"n\")](selectStart0, A8name /* H  */, A8name /* H  *" ascii
    $s3 = "newtonsCradle1 /* H  */ = \"start \"+picker+\"\\r\\nexit\"" fullword ascii
    $s4 = "dot1 /* H  */= true;/* H  */" fullword ascii
    $s5 = "function sDiv2(){return newtonsCradle0 /* H  */;};" fullword ascii

  condition:
    (uint16(0) == 0x6176 and (all of them)
    ) or (all of them)
}