rule _20160921_207d0a8168d3fb16019724b9f72c41ba_20160921_48288731baa0_1335 {
  meta:
    description = "datamaliciousorder - from files 20160921_207d0a8168d3fb16019724b9f72c41ba.js, 20160921_48288731baa006b25b4e98b12520da2b.js, 20160921_4c2bf112991da80cf65c9f462d7503be.js, 20160921_515ffdda2060abfddd0b1faaa82a6279.js, 20160921_58b4526aa2dc68b6db4250cf3153d1c5.js, 20160921_64fd82bf037f1ee6b74269456349f2e6.js, 20160921_67db5ecea174c85a1df44685d8781acd.js, 20160921_6bf1e6b71f68264911cd95f601a6cc98.js, 20160921_7e2de7c26f136a1a958818752613cac3.js, 20160921_8f9d19bbb031c21665ebbafad8d5ab55.js, 20160921_9c64236400e63181393ce4bc58f634a5.js, 20160921_9e9f1aaa0e051c856253652c93b64496.js, 20160921_a6679b5a153c4bb3f7cb9fe7c02dc710.js, 20160921_a7daa1622ff2bc3dccfc20f622902f7b.js, 20160921_bad084fc8365d25463811ce32bf91ceb.js, 20160921_cff8867bbb427ac014f0546c00ad8427.js, 20160921_dd3003e8f16270410cd847da3878f1fc.js, 20160921_e6771cfa257410eb61913de76cb777a8.js, 20160921_e67c85fc609bef1c06233d9dc655b074.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "90b56af8225bf5087b8c8ea31ab85a80e0951c3a32b8a0a0be7e09ef2efc8172"
    hash2       = "ce917015afcf31459cc47b8864f85394a756701f6338f6a2cbe079779c3ecd43"
    hash3       = "f2e5ee0ebdd9746b0055379071a47434cdd28be3788ad04e886f8bd01e0746c1"
    hash4       = "e66d45deceae626136192ed805b6d7d4dc1cb2be6956a53702353ef221f89c18"
    hash5       = "8879fc10234de7d36f536a9cdb49bc5cf37dfb897d610b0eeba644033852dd92"
    hash6       = "ba779a9cd5d48159c0b701ec2bc1832d098c0d5cf1f3a9429684810372bfa1b2"
    hash7       = "240705f58012306a07f93042172cd93e3bba16b8c9e0a9dd928f169ce059bf22"
    hash8       = "3380b40f96f91c57b2ab0fcc0353b9938919cdb262f565dd84233769eb1a8842"
    hash9       = "540bec3c8538992ab2a631157eae2d03acb2afd24ba0842fcdbbcd7a792913b3"
    hash10      = "b4039cc962a684523fe76faba20cbc27d33e0e6b0c86feb67e04127cf37a2fc4"
    hash11      = "2b1d27f440a3f4232e02265ce38f6eee5a715bff67e056aca1a1c800909c0e37"
    hash12      = "150de993662365ce2c7407195d1e62da40d5d5ecc67a4a3eb34985123077ada3"
    hash13      = "c54f97191e0c15791315cc1823b0fbce23679bebe5b1ce5c2b6b4895074c1121"
    hash14      = "4caa07134c114c6f14592ae1a6f87a08bd21b6048c96d44b5eb70d9762008059"
    hash15      = "047a9508e8bdaf65bc39b28d9eac8b287b7a434a3a0808290117a7b71d1d03f6"
    hash16      = "80a0b2154f5b0c87fb7ba82fc32a74807761d038a93d6da45f835417e93af3ef"
    hash17      = "484cc3f4c9cc3a29ae3ad53bb6d47be99d119531836a636c664a77fc891b38fc"
    hash18      = "009074e75815902f1e36daa21c179598b761767cd8d92eb363f3541838abdbfe"
    hash19      = "372b553e13a1b2dacf2c8938d6c7953212ff8112978d88f8aa1425ffa2ef21de"

  strings:
    $s1  = "unction fuck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Et\";})(),(function fuck(){retu" ascii
    $s2  = "turn \"We\";})(),(function fuck(){return \"FJs\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg\";})()," ascii
    $s3  = "ZWu\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"IPu\";})(),(functio" ascii
    $s4  = "(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){return \"Ik\";})(),(function fuck(" ascii
    $s5  = "nction fuck(){return \"Xw\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"USf\";})(),(function fuck(){retu" ascii
    $s6  = "eturn \"GJx\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"Mw\";})(),(function fuck(){return \"RAi\";})()," ascii
    $s7  = "on fuck(){return \"Cd\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return " ascii
    $s8  = "f\";})(),(function fuck(){return \"UXf\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"IPu\";})(),(functio" ascii
    $s9  = " fuck(){return \"IPu\";})(),(function fuck(){return \"Oh\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"I" ascii
    $s10 = "Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MIl\";})(),(function fuck(){return \"DAa\";})(),(functi" ascii
    $s11 = "tion fuck(){return \"IOs\";})(),(function fuck(){return \"YAv\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return" ascii
    $s12 = "),(function fuck(){return \"Cd\";})(),(function fuck(){return \"To\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){r" ascii
    $s13 = "n fuck(){return \"IPu\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"Q" ascii
    $s14 = "fuck(){return \"IPu\";})(),(function fuck(){return \"To\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){return \"IPu" ascii
    $s15 = "{return \"To\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg\";})(" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}