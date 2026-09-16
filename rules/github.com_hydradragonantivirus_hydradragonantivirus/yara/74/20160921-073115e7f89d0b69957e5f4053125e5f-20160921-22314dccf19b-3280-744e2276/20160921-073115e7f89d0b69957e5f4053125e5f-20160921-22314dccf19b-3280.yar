rule _20160921_073115e7f89d0b69957e5f4053125e5f_20160921_22314dccf19b_3280 {
  meta:
    description = "datamaliciousorder - from files 20160921_073115e7f89d0b69957e5f4053125e5f.js, 20160921_22314dccf19b7c672f3deae2294f4b16.js, 20160921_28d059ae521dbabe2afdc3bfd464938c.js, 20160921_297b9b66086a46a28327ea94b4a62e58.js, 20160921_2b1783136e2caa674fa83100212e0871.js, 20160921_40c9b3a004789873984432b531f4fb80.js, 20160921_50ddf5c101f65dbae1a99b5967b69eaf.js, 20160921_6167c3d38189e7b1134d16083ffbd574.js, 20160921_69015d5cf863b10983b8aa49b42d835e.js, 20160921_6b34f0b83cb5d89ac574db511a389f02.js, 20160921_74aa1eb054c4d9cf85bcad2468e8404a.js, 20160921_7912bf3790296273bb8c94248adbbc9a.js, 20160921_989b05bf7416ad8ff0b583666028a2c1.js, 20160921_d29f521c8121911a610a80bcc76b94bf.js, 20160921_daba59e7a6b9ed6983cd2cbef1eb1597.js, 20160921_ec2541ade561a4750092fda52be6f269.js, 20160921_f1aea308b2000a8d722d0f21c756fabf.js, 20160922_7e0b1e5964974c7e845016e40a3ad891.js, 20160922_b9c8ae1e2648708b7b599ba2ac6333c1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e1c8736261480d3d6df844d8e7fb92f64f1dc2bf84561d1b707e82daa456fef1"
    hash2       = "9361b0d332b84592c527454959eb22d4191bb17c4d1acc962c192e90e96fc83e"
    hash3       = "e141f467019579b96a9cc109c7a3e7efb3b51b1378b450a816089a6ae7d406f7"
    hash4       = "4d719bbec78475fb1d00242f1258699600032a10dd821cc9dfec2254bbe341f7"
    hash5       = "4f4f696f319827ea3bc8e0b927eddbd7a588f390148cae3276f1573d816d8889"
    hash6       = "b913ca9b6976b1846b7d36cab5b8fc09147f8eda84e9fde77f0aab4dfe5a2ab3"
    hash7       = "4d3df92f56e6b5cba10c96e8cd182f92f3c10aceaabe5a4530b70d3fc5873feb"
    hash8       = "02d7a73acd6af9940f585a0e89095467489ba0ac094eb93050d43dab5745e5bd"
    hash9       = "797bada2609e8fc67a8ede267e9fcce2fc817f630e6fe62c7953cc722eea6d2c"
    hash10      = "2483c88a0836510cd8b6af7b5d26f30c64147663cbbe75188bd12c828f642afa"
    hash11      = "74bb8f886c1de9aea157cf5ee2e1b8c02b30df1117e95e18ef3a2d5dc44277ad"
    hash12      = "3bf106f8ef0e4b03e869f1cf914513f711eb52824441a1f2740f3faec2821404"
    hash13      = "c3c2ebe9b3cb36288422e9757d55c015e9201e8ed349ea0a4f3fb5c4042fbfb3"
    hash14      = "e80237660128a774d0b2338e2d9c1fb4921908fa1f5ccbf74a87c0a04d0a8667"
    hash15      = "94c619539e853fdec1958270da7516c52bbcf442ee9ca0569d11e19e70ae29eb"
    hash16      = "1db7ed5a240fde30e4fca12eca866b9b96b56836ae50ea4c0fcf2d28b08be3b5"
    hash17      = "3175e432bce3be89acef4ff7215de666ea47cac857c8c07ff649c1cdd5484103"
    hash18      = "de6271315a5e75cb84cc0796ab51f8e68b1d166a3e7393cc14d81a37883277cd"
    hash19      = "e2b244eea80e558d4ae468572be8ba3fade8163b0f8751b10ba6ca2263421085"

  strings:
    $s1 = "turn \"Tn\";})(),(function f000(){return \"SGs\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"YTp\";})()," ascii
    $s2 = "tion f000(){return \"Wy\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"MJq\";})(),(function f000(){return " ascii
    $s3 = "n f000(){return \"BQb\";})(),(function f000(){return \"BQb\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"" ascii
    $s4 = "(),(function f000(){return \"Ml\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"NBs\";})(),(function f000()" ascii
    $s5 = ")(),(function f000(){return \"KXg\";})(),(function f000(){return \"KIc\";})(),(function f000(){return \"KIc\";})(),(function f00" ascii
    $s6 = "{return \"KIc\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"Mt\";})(),(function f000(){return \"UEg\";})" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}