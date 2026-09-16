rule _20160921_54ac484c468ac2ca7fe6c7210ca717bb_20160921_9d32b55f93b8_661 {
  meta:
    description = "datamaliciousorder - from files 20160921_54ac484c468ac2ca7fe6c7210ca717bb.js, 20160921_9d32b55f93b83e117524c4df15361eee.js, 20160921_a1cbb43a1e22a4b1fd63ee1a724173eb.js, 20160921_b8c98d7e4e5c69c2f4fa4fec37a59dfb.js, 20160921_da7f7f057c35b886425ec822f654da90.js, 20160921_dd28b3b2e4fae279f1dc4ba30acafda9.js, 20160922_b06824c3d57db547b98db8d6b10525d0.js, 20160922_ddc158d1b0906f773c8ee4447daa25e5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5b883334540a4216b3582d1f2fa0a27f21b9c64a87944c8e58d9fab0f609eef3"
    hash2       = "3fe6572823305aa2316dd2ce562c85b9f6eb40f26ee354b5e0ff97b66cffd652"
    hash3       = "4154e4928eccd35fa0d42dbefe4a742700d77124216f8b5756b8ef63634071d3"
    hash4       = "f1ea05bc317ec861954db64b30bd293d8ee2f663106d48389d91cfb77247fb1e"
    hash5       = "b6935463e925cb13fc2413b3d7559cf8e9f5072c15dc73075977046a3e27e417"
    hash6       = "841abb0789337235f3a5367c6d4aa3806741a639f1faf0d54e41f125ecc1be02"
    hash7       = "73bcfec2ac113640d73b2ea0f0c348d7bc7d672d6be74cb4398f8669b599694b"
    hash8       = "da7f290c48869e8adc8a27e6344a762283ddaa55eae77000c5439a118d259a98"

  strings:
    $s1  = "t\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"Oe\";})(),(function " ascii
    $s2  = "n f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"Y" ascii
    $s3  = "})(),(function f000(){return \"UEg\";})(),(function f000(){return \"Mt\";})(),(function f000(){return \"UEg\";})(),(function f00" ascii
    $s4  = "f000(){return \"KXg\";})(),(function f000(){return \"KIc\";})(),(function f000(){return \"KIc\";})(),(function f000(){return \"T" ascii
    $s5  = "function f000(){return \"Lp\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"GGn\";})(),(function f000(){ret" ascii
    $s6  = "),(function f000(){return \"ZFe\";})(),(function f000(){return \"Nx\";})(),(function f000(){return \"Lp\";})(),(function f000(){" ascii
    $s7  = "f000(){return \"MMz\";})(),(function f000(){return \"DAp\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"DY" ascii
    $s8  = "rn \"KDh\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"Kw\";})(),(fun" ascii
    $s9  = "on f000(){return \"UEg\";})(),(function f000(){return \"Uo\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"" ascii
    $s10 = "\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"Sq\";})(),(function f" ascii
    $s11 = "),(function f000(){return \"TKl\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"KIc\";})(),(function f000()" ascii
    $s12 = "function f000(){return \"Br\";})(),(function f000(){return \"Fs\";})(),(function f000(){return \"MBb\";})(),(function f000(){ret" ascii
    $s13 = "n \"BQb\";})(),(function f000(){return \"BQb\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"KXg\";})(),(fu" ascii
    $s14 = "){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"Um\";})" ascii
    $s15 = "turn \"Wy\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"Yi\";})(),(f" ascii
    $s16 = "function f000(){return \"MBb\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"DAp\";})(),(function f000(){re" ascii
    $s17 = "ction f000(){return \"Oe\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"DAp\";})(),(function f000(){retur" ascii
    $s18 = "000(){return \"GGn\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"MBb" ascii
    $s19 = "tion f000(){return \"Wy\";})(),(function f000(){return \"Fs\";})(),(function f000(){return \"KIc\";})(),(function f000(){return " ascii
    $s20 = "000(){return \"YTp\";})(),(function f000(){return \"BQb\";})(),(function f000(){return \"BQb\";})(),(function f000(){return \"Yi" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}