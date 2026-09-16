rule _20160921_bc3224e9a637b2113b3de820bcee66c0_20160921_d56a785468c6_4039 {
  meta:
    description = "datamaliciousorder - from files 20160921_bc3224e9a637b2113b3de820bcee66c0.js, 20160921_d56a785468c6ab02ba1f7ee3a5eadcdb.js, 20160921_df47c7f57f308287ca344dcc34150b37.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "65d11827de99ef59cd2cc61d914e235dd2b16ac6b8f4f65f39b8a79dad86ed57"
    hash2       = "d5ca39f97274b051212868ee58d01e745bb87d0a12198dfdfbeb7c3965cbf540"
    hash3       = "dbb4502419f8afb7a2d5fc4186a2c7922701956498b55deb8c27312672415d9c"

  strings:
    $s1 = "unction fuck(){return \"DRx\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){retu" ascii
    $s2 = "{return \"Dc\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})" ascii
    $s3 = "return \"IPu\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"ZLd\";})(),(function fuck(){return \"Jg\";})()" ascii
    $s4 = "n \"Jh\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"Wo0\";})(),(fu" ascii
    $s5 = "uck(){return \"Py\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){return \"Sx\"" ascii
    $s6 = "),(function fuck(){return \"IRn\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"To\";})(),(function fuck()" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}