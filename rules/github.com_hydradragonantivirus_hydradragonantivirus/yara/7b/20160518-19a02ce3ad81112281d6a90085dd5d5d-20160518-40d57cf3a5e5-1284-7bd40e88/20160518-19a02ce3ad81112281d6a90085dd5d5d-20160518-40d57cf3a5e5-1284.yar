rule _20160518_19a02ce3ad81112281d6a90085dd5d5d_20160518_40d57cf3a5e5_1284 {
  meta:
    description = "datamaliciousorder - from files 20160518_19a02ce3ad81112281d6a90085dd5d5d.js, 20160518_40d57cf3a5e569a50bff8ee415b49f6b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9cdf8e5a456994a6cebbae03bb8f24364e56ff58b1775045ff8c5f6ddbb46a62"
    hash2       = "6d9aeb8ee3c93f067210253d76cceb646f0e0e99bdfd81392a59e9eb6469c8f8"

  strings:
    $s1 = "solid1[CAD](getAttribute0 /* I  */, dingy, (true, false));" fullword ascii
    $s2 = "function sDiv2(){return newtonsCradle0 /* I  */;};" fullword ascii
    $s3 = "newtonsCradle1 /* I  */ = \"start \"+picker+\"\\r\\nexit\"" fullword ascii
    $s4 = "function doled(selectStart0){doled1[(\"3\", \"2\", \"R\")+ \"u\" + (\"1\", \"n\")](selectStart0, A8name /* I  */, A8name /* I  *" ascii
    $s5 = "dot1 /* I  */= true;/* I  */" fullword ascii

  condition:
    (uint16(0) == 0x6176 and (all of them)
    ) or (all of them)
}