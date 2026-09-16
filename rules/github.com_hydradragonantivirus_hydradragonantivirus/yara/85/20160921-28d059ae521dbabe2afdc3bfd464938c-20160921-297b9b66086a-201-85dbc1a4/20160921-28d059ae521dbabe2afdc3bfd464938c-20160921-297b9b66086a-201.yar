rule _20160921_28d059ae521dbabe2afdc3bfd464938c_20160921_297b9b66086a_201 {
  meta:
    description = "datamaliciousorder - from files 20160921_28d059ae521dbabe2afdc3bfd464938c.js, 20160921_297b9b66086a46a28327ea94b4a62e58.js, 20160921_2b1783136e2caa674fa83100212e0871.js, 20160921_40c9b3a004789873984432b531f4fb80.js, 20160921_6167c3d38189e7b1134d16083ffbd574.js, 20160921_7912bf3790296273bb8c94248adbbc9a.js, 20160921_daba59e7a6b9ed6983cd2cbef1eb1597.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e141f467019579b96a9cc109c7a3e7efb3b51b1378b450a816089a6ae7d406f7"
    hash2       = "4d719bbec78475fb1d00242f1258699600032a10dd821cc9dfec2254bbe341f7"
    hash3       = "4f4f696f319827ea3bc8e0b927eddbd7a588f390148cae3276f1573d816d8889"
    hash4       = "b913ca9b6976b1846b7d36cab5b8fc09147f8eda84e9fde77f0aab4dfe5a2ab3"
    hash5       = "02d7a73acd6af9940f585a0e89095467489ba0ac094eb93050d43dab5745e5bd"
    hash6       = "3bf106f8ef0e4b03e869f1cf914513f711eb52824441a1f2740f3faec2821404"
    hash7       = "94c619539e853fdec1958270da7516c52bbcf442ee9ca0569d11e19e70ae29eb"

  strings:
    $s1  = "eturn \"Br\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"Br\";})(),(" ascii
    $s2  = "ction f000(){return \"GGn\";})(),(function f000(){return \"Go\";})(),(function f000(){return \"BMj\";})(),(function f000(){retur" ascii
    $s3  = "tion f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Lp\";})(),(function f000(){return " ascii
    $s4  = "{return \"MBb\";})(),(function f000(){return \"Mc\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";})" ascii
    $s5  = "ion f000(){return \"DAp\";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"Km\";})(),(function f000(){return " ascii
    $s6  = "n \"DAp\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"Nx\";})(),(function f000(){return \"Br\";})(),(func" ascii
    $s7  = "{return \"Oe\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";})" ascii
    $s8  = "f000(){return \"Vj\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Ml\";})(),(function f000(){return \"Br" ascii
    $s9  = "0(){return \"MMz\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"GGn\"" ascii
    $s10 = "){return \"Sq\";})(),(function f000(){return \"BQb\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"DYx\";}" ascii
    $s11 = "ction f000(){return \"WIj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Br\";})(),(function f000(){retur" ascii
    $s12 = "000(){return \"Yz\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj" ascii
    $s13 = "n f000(){return \"Nv\";})(),(function f000(){return \"Nx\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"G" ascii
    $s14 = "00(){return \"Sv\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"GGn\"" ascii
    $s15 = "unction f000(){return \"Tb\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"GGn\";})(),(function f000(){retu" ascii
    $s16 = "on f000(){return \"Br\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"" ascii
    $s17 = "urn \"IAa\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";})(),(" ascii
    $s18 = "function f000(){return \"Mc\";})(),(function f000(){return \"BQb\";})(),(function f000(){return \"Iq\";})(),(function f000(){ret" ascii
    $s19 = "return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Tb\";})(),(function f000(){return \"EZu\";})()" ascii
    $s20 = "\"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Tb\";})(),(function f000(){return \"Vu\";})(),(functi" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}