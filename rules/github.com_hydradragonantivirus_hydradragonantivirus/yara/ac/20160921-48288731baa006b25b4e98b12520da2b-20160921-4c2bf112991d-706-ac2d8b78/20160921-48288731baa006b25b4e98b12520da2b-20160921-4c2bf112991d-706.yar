rule _20160921_48288731baa006b25b4e98b12520da2b_20160921_4c2bf112991d_706 {
  meta:
    description = "datamaliciousorder - from files 20160921_48288731baa006b25b4e98b12520da2b.js, 20160921_4c2bf112991da80cf65c9f462d7503be.js, 20160921_515ffdda2060abfddd0b1faaa82a6279.js, 20160921_58b4526aa2dc68b6db4250cf3153d1c5.js, 20160921_6bf1e6b71f68264911cd95f601a6cc98.js, 20160921_7e2de7c26f136a1a958818752613cac3.js, 20160921_8f9d19bbb031c21665ebbafad8d5ab55.js, 20160921_9c64236400e63181393ce4bc58f634a5.js, 20160921_a6679b5a153c4bb3f7cb9fe7c02dc710.js, 20160921_cff8867bbb427ac014f0546c00ad8427.js, 20160921_e67c85fc609bef1c06233d9dc655b074.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ce917015afcf31459cc47b8864f85394a756701f6338f6a2cbe079779c3ecd43"
    hash2       = "f2e5ee0ebdd9746b0055379071a47434cdd28be3788ad04e886f8bd01e0746c1"
    hash3       = "e66d45deceae626136192ed805b6d7d4dc1cb2be6956a53702353ef221f89c18"
    hash4       = "8879fc10234de7d36f536a9cdb49bc5cf37dfb897d610b0eeba644033852dd92"
    hash5       = "3380b40f96f91c57b2ab0fcc0353b9938919cdb262f565dd84233769eb1a8842"
    hash6       = "540bec3c8538992ab2a631157eae2d03acb2afd24ba0842fcdbbcd7a792913b3"
    hash7       = "b4039cc962a684523fe76faba20cbc27d33e0e6b0c86feb67e04127cf37a2fc4"
    hash8       = "2b1d27f440a3f4232e02265ce38f6eee5a715bff67e056aca1a1c800909c0e37"
    hash9       = "c54f97191e0c15791315cc1823b0fbce23679bebe5b1ce5c2b6b4895074c1121"
    hash10      = "80a0b2154f5b0c87fb7ba82fc32a74807761d038a93d6da45f835417e93af3ef"
    hash11      = "372b553e13a1b2dacf2c8938d6c7953212ff8112978d88f8aa1425ffa2ef21de"

  strings:
    $s1  = "})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"GJx\";})(),(function fuck(){return \"MUs\";})(),(function fu" ascii
    $s2  = "fuck(){return \"IPu\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){return \"IOs" ascii
    $s3  = "eturn \"IPu\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"To\";})(),(function fuck(){return \"Xg\";})(),(" ascii
    $s4  = "(){return \"MBg\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"IPu\";" ascii
    $s5  = "ion fuck(){return \"IPu\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"OPz\";})(),(function fuck(){return " ascii
    $s6  = "rn \"Xw\";})(),(function fuck(){return \"KVh\";})(),(function fuck(){return \"Jg\";})(),(function fuck(){return \"Xw\";})(),(fun" ascii
    $s7  = "ction fuck(){return \"Xw\";})(),(function fuck(){return \"Ug\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return " ascii
    $s8  = "k(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"YQt\";" ascii
    $s9  = "ion fuck(){return \"Xw\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return " ascii
    $s10 = "{return \"IPu\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){return \"XCr\";})(),(function fuck(){return \"AUx\";})" ascii
    $s11 = "})(),(function fuck(){return \"IOs\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg\";})(),(function fu" ascii
    $s12 = "){return \"Nm\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg\";})" ascii
    $s13 = "\"Ar\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg\";})(),(func" ascii
    $s14 = "(function fuck(){return \"Xg\";})(),(function fuck(){return \"ZLd\";})(),(function fuck(){return \"Mw\";})(),(function fuck(){re" ascii
    $s15 = "){return \"Xw\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"Dc\";})()" ascii
    $s16 = "n \"IPu\";})(),(function fuck(){return \"GJx\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){return \"Sx\";})(),(fu" ascii
    $s17 = "){return \"IPu\";})(),(function fuck(){return \"ZLd\";})(),(function fuck(){return \"Ug\";})(),(function fuck(){return \"UXf\";}" ascii
    $s18 = "turn \"XFd\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"IPu\";})()," ascii
    $s19 = "nction fuck(){return \"Dc\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){retu" ascii
    $s20 = "n \"IPu\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(fun" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}