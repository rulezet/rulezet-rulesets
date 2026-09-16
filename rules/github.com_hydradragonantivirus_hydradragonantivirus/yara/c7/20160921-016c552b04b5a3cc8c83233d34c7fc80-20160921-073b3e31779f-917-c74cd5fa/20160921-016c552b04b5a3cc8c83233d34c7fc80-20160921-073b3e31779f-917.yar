rule _20160921_016c552b04b5a3cc8c83233d34c7fc80_20160921_073b3e31779f_917 {
  meta:
    description = "datamaliciousorder - from files 20160921_016c552b04b5a3cc8c83233d34c7fc80.js, 20160921_073b3e31779f349650fc6977a0add94b.js, 20160921_1af58d1231756b320d04226685b5a131.js, 20160921_334dc22c3620386c4119de547e0c0f38.js, 20160921_54ac484c468ac2ca7fe6c7210ca717bb.js, 20160921_73b5a50d06622b8411077815f2717627.js, 20160921_9d32b55f93b83e117524c4df15361eee.js, 20160921_a1cbb43a1e22a4b1fd63ee1a724173eb.js, 20160921_b8c98d7e4e5c69c2f4fa4fec37a59dfb.js, 20160921_cb7b906c44a337d403a375918e9db0c5.js, 20160921_da7f7f057c35b886425ec822f654da90.js, 20160921_dd28b3b2e4fae279f1dc4ba30acafda9.js, 20160922_b06824c3d57db547b98db8d6b10525d0.js, 20160922_ddc158d1b0906f773c8ee4447daa25e5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a691692f0982e93fd21c441e8c6d39328f1ea5990ce24999b2df98ee3488f667"
    hash2       = "60d01505d8ea4f2da2961c36fda33950e39ba720d54d967d434c0c5003ff7d2f"
    hash3       = "de59166ad132c3c5ad12a85d2d837c1aec192afb497be23c517c637a08d25171"
    hash4       = "a69d8e08a2b4320b4183bfad7a1baa8fc49b7361116aeb9e3a542ae416cd93d5"
    hash5       = "5b883334540a4216b3582d1f2fa0a27f21b9c64a87944c8e58d9fab0f609eef3"
    hash6       = "ff8a171dec88d707916b1928e49d84c61474fe9b0faf2916e72eadb2b404d04b"
    hash7       = "3fe6572823305aa2316dd2ce562c85b9f6eb40f26ee354b5e0ff97b66cffd652"
    hash8       = "4154e4928eccd35fa0d42dbefe4a742700d77124216f8b5756b8ef63634071d3"
    hash9       = "f1ea05bc317ec861954db64b30bd293d8ee2f663106d48389d91cfb77247fb1e"
    hash10      = "2a06a7a374bfacf6c8c177295f8ab5c8e4e8db511406cc33fcef97866f72f9dc"
    hash11      = "b6935463e925cb13fc2413b3d7559cf8e9f5072c15dc73075977046a3e27e417"
    hash12      = "841abb0789337235f3a5367c6d4aa3806741a639f1faf0d54e41f125ecc1be02"
    hash13      = "73bcfec2ac113640d73b2ea0f0c348d7bc7d672d6be74cb4398f8669b599694b"
    hash14      = "da7f290c48869e8adc8a27e6344a762283ddaa55eae77000c5439a118d259a98"

  strings:
    $s1  = "rn \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"DNa\";})(),(fu" ascii
    $s2  = "rn \"Br\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"Wy\";})(),(fun" ascii
    $s3  = "\"Br\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"GGn\";})(),(funct" ascii
    $s4  = "on f000(){return \"Ml\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"Go\";})(),(function f000(){return \"B" ascii
    $s5  = ")(),(function f000(){return \"RVb\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"GGn\";})(),(function f00" ascii
    $s6  = "function f000(){return \"Oe\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"GGn\";})(),(function f000(){re" ascii
    $s7  = "000(){return \"SGs\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"GGn" ascii
    $s8  = " f000(){return \"Vj\";})(),(function f000(){return \"Nx\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WI" ascii
    $s9  = "f000(){return \"Go\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"GGn" ascii
    $s10 = "\"Ml\";})(),(function f000(){return \"Uo\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"TKp\";})(),(functi" ascii
    $s11 = ",(function f000(){return \"Ml\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Ml\";})(),(function f000(){re" ascii
    $s12 = "000(){return \"Br\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"Br\"" ascii
    $s13 = ",(function f000(){return \"Br\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"Wy\";})(),(function f000(){re" ascii
    $s14 = "turn \"Br\";})(),(function f000(){return \"Go\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"Qa\";})(),(f" ascii
    $s15 = "on f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"HJm\";})(),(function f000(){return " ascii
    $s16 = "000(){return \"Uo\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"KDh" ascii
    $s17 = "tion f000(){return \"GGn\";})(),(function f000(){return \"Go\";})(),(function f000(){return \"Vu\";})(),(function f000(){return " ascii
    $s18 = "00(){return \"GGn\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return \"Mc" ascii
    $s19 = " f000(){return \"KDh\";})(),(function f000(){return \"HJm\";})(),(function f000(){return \"HJm\";})(),(function f000(){return \"" ascii
    $s20 = "urn \"Br\";})(),(function f000(){return \"DAp\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"Nx\";})(),(fu" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}