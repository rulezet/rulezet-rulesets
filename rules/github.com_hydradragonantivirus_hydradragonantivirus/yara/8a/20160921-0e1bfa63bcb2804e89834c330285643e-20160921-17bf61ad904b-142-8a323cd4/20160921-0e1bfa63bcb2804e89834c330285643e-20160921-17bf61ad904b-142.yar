rule _20160921_0e1bfa63bcb2804e89834c330285643e_20160921_17bf61ad904b_142 {
  meta:
    description = "datamaliciousorder - from files 20160921_0e1bfa63bcb2804e89834c330285643e.js, 20160921_17bf61ad904bb1d3a22ca03d861f889f.js, 20160921_3214ea252f2a25e018a03ee43ce952f5.js, 20160921_78345276f684d53628bbcac810994182.js, 20160921_87ced6523e47b3b752b2353107bc989a.js, 20160921_945a46518061bd8e157aed251e0ffa9e.js, 20160921_95c689d7ff4700a03d604b71aaf3634b.js, 20160921_ad1fccc6910bd9c4a47aa9bd3e9239da.js, 20160921_b5efb4ba3e712545d64a2d00b3dcd76e.js, 20160921_d29f34806a7d94f2bbb7a733fc4c43bc.js, 20160921_d4e094c14df45f61de0e1163f51e03e6.js, 20160921_e39622eeb1da8fbbf03ca86989251a47.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d58b57cb825244d35e22402fcf08c9ababcc51eb72a7913c47dbb2143171df32"
    hash2       = "3ad9770f05718e622431ef5405e0a702ec2484ecc5b434b1a634c99b480bc855"
    hash3       = "e406c80b4ad80ad1898c09cec0694086bfb24caedb8bc3bb213513d0b4232bd3"
    hash4       = "17b203684b4f2284de883c81e8fef63ea03c36bd0599ccb85d3175be35d9ac6d"
    hash5       = "46c521beb23d37cfa4d60cfcab38c941734971fe3102123b7e4c2813544d39b6"
    hash6       = "cc3d236edb3b45a767b438fa21243a07176d6f5def724e03e45aca76b3127054"
    hash7       = "5783f1dc6f93c438a9ac56abe49d6a41942b0b140e5fe608a7748f646ea646e7"
    hash8       = "a49fc1cb85eaa58b7c63197e9fd25224f63dcb6c86b906933f698898634ead3e"
    hash9       = "ff8ef85b589636068d365f9ee4a0b9c7119baeb269d0a34c9810fca4b3faf1cf"
    hash10      = "70ffc02d6ba6dee7d11e2b608cd1544f99d837ffc746455c17b70d5b07ba0ac9"
    hash11      = "2877b2ace685858babd88dd0ef1659f49f21c3f8b907e5b3889ec46bf3a7104a"
    hash12      = "e0b1660f1c95284f1a0f8062a1f16e26aa3d58e3fa4cf47fc04824d02b754a56"

  strings:
    $s1  = "\"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"MIl\";})(),(funct" ascii
    $s2  = "{return \"GJx\";})(),(function fuck(){return \"KVh\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"IPu\";}" ascii
    $s3  = " fuck(){return \"IPu\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"XCr\";})(),(function fuck(){return \"X" ascii
    $s4  = "urn \"Xw\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"ZLd\";})(),(f" ascii
    $s5  = "nction fuck(){return \"IPu\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"To\";})(),(function fuck(){retur" ascii
    $s6  = "n \"Dc\";})(),(function fuck(){return \"YAv\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"IPu\";})(),(fun" ascii
    $s7  = "(){return \"Dc\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"IPu\";})" ascii
    $s8  = "rn \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"XHj\";})(),(fu" ascii
    $s9  = ";})(),(function fuck(){return \"UXf\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"Fv\";})(),(function fuc" ascii
    $s10 = "return \"DAa\";})(),(function fuck(){return \"Pc\";})(),(function fuck(){return \"Ug\";})(),(function fuck(){return \"Dc\";})()," ascii
    $s11 = "ion fuck(){return \"Zy\";})(),(function fuck(){return \"GJx\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return " ascii
    $s12 = "})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"Wn\";})(),(function fuc" ascii
    $s13 = "(),(function fuck(){return \"Pc\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){return \"Vf\";})(),(function fuck(){" ascii
    $s14 = "uck(){return \"Xw\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"IPu" ascii
    $s15 = "function fuck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"We\";})(),(function fuck(){ret" ascii
    $s16 = "rn \"IPu\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"Av\";})(),(fu" ascii
    $s17 = " fuck(){return \"Xw\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"Mw\";})(),(function fuck(){return \"UXf" ascii
    $s18 = "nction fuck(){return \"GJx\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){retu" ascii
    $s19 = "turn \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ug\";})(),(function fuck(){return \"XHj\";})(),(" ascii
    $s20 = "k(){return \"GWo\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"EHo\";})(),(function fuck(){return \"ADy\"" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}