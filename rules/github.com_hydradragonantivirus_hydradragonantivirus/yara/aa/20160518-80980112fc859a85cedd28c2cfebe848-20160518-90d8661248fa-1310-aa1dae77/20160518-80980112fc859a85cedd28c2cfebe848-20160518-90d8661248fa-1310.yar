rule _20160518_80980112fc859a85cedd28c2cfebe848_20160518_90d8661248fa_1310 {
  meta:
    description = "datamaliciousorder - from files 20160518_80980112fc859a85cedd28c2cfebe848.js, 20160518_90d8661248fa4cece0661bf443799eac.js, 20160518_db00ea9c09cf68ed495a999b4e2e268b.js, 20160518_e2d8a8f00eb5a69e67e395d938216fa3.js, 20160519_0e214d970829c12f5eba3ebad969bc8c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6b7982f786deb9e09dfd63af9752a16edd4c9251f30cf54d5ae5b92f239c475b"
    hash2       = "ef0e874d99963dd92de3b00cda6b6979dc641dd16a8efe2eac582577e36b099f"
    hash3       = "614f15f721da6d67971ab8309abcc3f3e257cceab58b0e52e8c3492b6abb328c"
    hash4       = "55ff51af65dbb51b87d95323a9474eb19b2a11be17f888a2b8bbb89887db01be"
    hash5       = "95e69e80fb834625a5549d321091431923def6f68443dc40adce4866793fff7d"

  strings:
    $s1 = "solid1[CAD](getAttribute0 /* B  */, dingy, (true, false));" fullword ascii
    $s2 = "dot1 /* B  */= true;/* B  */" fullword ascii
    $s3 = "function doled(selectStart0){doled1[(\"3\", \"2\", \"R\")+ \"u\" + (\"1\", \"n\")](selectStart0, A8name /* B  */, A8name /* B  *" ascii
    $s4 = "newtonsCradle1 /* B  */ = \"start \"+picker+\"\\r\\nexit\"" fullword ascii
    $s5 = "function sDiv2(){return newtonsCradle0 /* B  */;};" fullword ascii

  condition:
    (uint16(0) == 0x6176 and (all of them)
    ) or (all of them)
}