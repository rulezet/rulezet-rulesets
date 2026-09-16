rule _20160921_1766f5c818d6371cb36488c98158ccd2_20160921_17bab7cc945f_3419 {
  meta:
    description = "datamaliciousorder - from files 20160921_1766f5c818d6371cb36488c98158ccd2.js, 20160921_17bab7cc945fd06123e7b9b16dea263f.js, 20160921_1b3a88384cf704def4ce92e01728a1df.js, 20160921_f5decbca2e5a35bbb5c42091c1b0c30e.js, 20160921_fe8abdad2bc00d1378e2964402e33217.js, 20160922_c593174721c6fbd1b57bf98d8a85a6fd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4d8985b767534ef1312401b6a38570477e0c87ed4ef37c945eee55179929c0a4"
    hash2       = "a1dd80ed4e2509af999afcf84c8f78ecc409616f9d6e072d25cb980d8bf9e464"
    hash3       = "dc931c610cc8536a2b67001c5b7c93e6dc26026d0daa00576bf3e92b3bd564a7"
    hash4       = "5fe03908bd7d860f1260a3264b2e10de3115d24242a095cf4c0b73e7934ce89e"
    hash5       = "39d0496129988da40dbbddcff6610a39be1f05ddd7f48a13058b749810c8400d"
    hash6       = "c85cab0d5b0c79fe38ee2b60c2ea7eca36bb7dbe9442cff0a497346184cecee8"

  strings:
    $s1 = ")(),(function f000(){return \"Vu\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"GGn\";})(),(function f000(" ascii
    $s2 = "f000(){return \"DYx\";})(),(function f000(){return \"Ml\";})(),(function f000(){return \"DNa\";})(),(function f000(){return \"Oe" ascii
    $s3 = "(){return \"Vj\";})(),(function f000(){return \"Nx\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"Zj\";})" ascii
    $s4 = "rn \"WIj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"UEg\";})(),(f" ascii
    $s5 = "(function f000(){return \"Wy\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"Iq\";})(),(function f000(){re" ascii
    $s6 = "BQb\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"DNa\";})(),(functi" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}