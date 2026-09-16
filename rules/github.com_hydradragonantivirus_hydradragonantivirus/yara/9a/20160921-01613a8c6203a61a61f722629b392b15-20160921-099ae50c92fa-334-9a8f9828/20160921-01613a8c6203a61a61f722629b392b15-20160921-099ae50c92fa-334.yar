rule _20160921_01613a8c6203a61a61f722629b392b15_20160921_099ae50c92fa_334 {
  meta:
    description = "datamaliciousorder - from files 20160921_01613a8c6203a61a61f722629b392b15.js, 20160921_099ae50c92fa9b72abe88204de915580.js, 20160921_67612c4ac75c1d3511dd9358b66e9fc5.js, 20160921_70fc4d2c06ba17e1c952591e28e14cf8.js, 20160921_718cbfc32cb1f435745a5a005d3f190b.js, 20160921_74a9afe189b59f0b8148a7f92f42b125.js, 20160921_76157564ae9f7ad7ec97100684b2a5ce.js, 20160921_8753c13c904d4c1e9e4a848591336ee8.js, 20160921_8f9ae4533bfbaedf1feae61032904250.js, 20160921_bc3224e9a637b2113b3de820bcee66c0.js, 20160921_c01f87df9de4ce5ca88bd5f8e99b8421.js, 20160921_cd62091b54940830ea3695d380fd97d8.js, 20160921_d03dc2f478ae343430b4a6dbcc9d6c08.js, 20160921_d56a785468c6ab02ba1f7ee3a5eadcdb.js, 20160921_df47c7f57f308287ca344dcc34150b37.js, 20160921_e354814fb0864710c25f5e3e9db82ed9.js, 20160921_e6977bb87c752a8f54937489e4d135c8.js, 20160921_f42ed060a223d31bf315f08c4c668579.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7c3ee763f1740e8bc6ded9772aabbe3d3805d8cf2a023e0289a9b8a1a42624b7"
    hash2       = "344e6822e369c3beb064ffee655d0ce0db901d1bada577cd8f338fc2aec06cb8"
    hash3       = "fbf6986e3a8c7defa5c14d80cff4f3b3ce1db859ea94044f5d024758684178c0"
    hash4       = "439af0812c2462e15038b6b3de132befd472f89a6810bf0f930acba54e4873ad"
    hash5       = "7611b8615a5a07f89bc6a867e9232ae443f0ff2bb48d960d2254e1390a27fdee"
    hash6       = "5ce6bfd72ee0a8f8259b2cfbaa6f5b49ec72ab64b03caf4bd2a4f733ef96925b"
    hash7       = "960b4c3b10bb54428dc28efdb559a533d7fe3cb117049c83d2a02862d8ec99f0"
    hash8       = "57611d1ad2ff9881d73dbaf53bfa8657402affd956dea32b9fc2afae375ffb9f"
    hash9       = "f093836b93b9b87ed10341ee30bc818ac497c91c6d0dd2b00ab5d3b1822868f9"
    hash10      = "65d11827de99ef59cd2cc61d914e235dd2b16ac6b8f4f65f39b8a79dad86ed57"
    hash11      = "863f188b1216c3a7a1dc561983400a4e8b6fadded702cf47ee8533061495abc8"
    hash12      = "e00553588533d1015b71812c5877864382cbfd2a3a204b4cab76c38ee65ce58c"
    hash13      = "dd1077874fb7f556e5acfe2ff0c2ed6b6c203fcdf442119ca307096446d90cd4"
    hash14      = "d5ca39f97274b051212868ee58d01e745bb87d0a12198dfdfbeb7c3965cbf540"
    hash15      = "dbb4502419f8afb7a2d5fc4186a2c7922701956498b55deb8c27312672415d9c"
    hash16      = "404a4224fa8dcbc9877419bc0d572bd67181c29f5eb3b1cff437b90863907b45"
    hash17      = "b2ce1297f179a619d69aa5fa99bb53216eba4d290e545dddda5d0a561f760ec0"
    hash18      = "e1af3f6144c617b4734d9d1f2ae999f7e6d3a46f08760085978213f7cbc38bce"

  strings:
    $s1  = "})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){return \"Xw\";})(),(function fuck(" ascii
    $s2  = "\";})(),(function fuck(){return \"GWo\";})(),(function fuck(){return \"Na\";})(),(function fuck(){return \"IPu\";})(),(function " ascii
    $s3  = "ion fuck(){return \"Fv\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"" ascii
    $s4  = "return \"MBg\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"We\";})()" ascii
    $s5  = "{return \"Ot\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"EHo\";})(),(function fuck(){return \"Vb\";})(" ascii
    $s6  = "n \"YAv\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"Xw\";})(),(fun" ascii
    $s7  = "a\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"Oh\";})(),(function" ascii
    $s8  = "eturn \"Nm\";})(),(function fuck(){return \"DAa\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg\";})()" ascii
    $s9  = "rn \"IPu\";})(),(function fuck(){return \"Oh\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"GNm\";})(),(fu" ascii
    $s10 = "),(function fuck(){return \"XFd\";})(),(function fuck(){return \"Mw\";})(),(function fuck(){return \"KVh\";})(),(function fuck()" ascii
    $s11 = "ction fuck(){return \"IPu\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return" ascii
    $s12 = "fuck(){return \"GWo\";})(),(function fuck(){return \"Wo0\";})(),(function fuck(){return \"ZVi\";})(),(function fuck(){return \"R" ascii
    $s13 = "n \"Za\";})(),(function fuck(){return \"EHo\";})(),(function fuck(){return \"UXf\";})(),(function fuck(){return \"KVh\";})(),(fu" ascii
    $s14 = "eturn \"Xw\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"Xw\";})(),(" ascii
    $s15 = "(){return \"SUi\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg\"" ascii
    $s16 = "urn \"XFd\";})(),(function fuck(){return \"Na\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"IPu\";})(),(" ascii
    $s17 = " fuck(){return \"Jo\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"IPu" ascii
    $s18 = "uck(){return \"YQt\";})(),(function fuck(){return \"GWo\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"IPu" ascii
    $s19 = "turn \"IPu\";})(),(function fuck(){return \"MIl\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"Py\";})(),(" ascii
    $s20 = "ction fuck(){return \"Oh\";})(),(function fuck(){return \"Vf\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return " ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}