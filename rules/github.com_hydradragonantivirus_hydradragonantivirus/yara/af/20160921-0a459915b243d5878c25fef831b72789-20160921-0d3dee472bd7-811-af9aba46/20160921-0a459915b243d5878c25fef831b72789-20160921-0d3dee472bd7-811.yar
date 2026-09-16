rule _20160921_0a459915b243d5878c25fef831b72789_20160921_0d3dee472bd7_811 {
  meta:
    description = "datamaliciousorder - from files 20160921_0a459915b243d5878c25fef831b72789.js, 20160921_0d3dee472bd7a0a1e2c48044e2c47f0b.js, 20160921_16200453422b5793a6a93d4bb423b0ea.js, 20160921_382a0f9b1ae693f8ade627fd2d6a8b52.js, 20160921_4787695fef4453a16be881bbe0f96c1a.js, 20160921_54325d6949c5c03d42a42e11b24dee5c.js, 20160921_5f0fd6cffcc723799fdcc54a3c2a7ba5.js, 20160921_60c26fdfafa2666b92246aea46e32175.js, 20160921_6748b4ad3c83a7c4aeacfc0817a81797.js, 20160921_a39f22c0c39a7d5bb3c55dd00a36b5b1.js, 20160921_b18e047e5b3fa2131425e272781d97b4.js, 20160921_c86a534fb694b7c269b48a9dc32f8a87.js, 20160921_cdeac57ac549120611856c7af0c490f6.js, 20160921_d6e5226f779c21f4fc4b67aeddca2869.js, 20160921_f9054cc04d83c2e4156f98873a8df799.js, 20160921_fbc9133aa5350aa4ce872cb5927c8f4f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9f8d1944044e8a67a527f50e4aeb45e9358929b0d0f7aaf1730d2782f07a09de"
    hash2       = "9ffda0cd0cd96558031ec49484507d0af3efe8f0ec6fee33e947b4b9515ab24f"
    hash3       = "d968eb9bb2807e5889794bf130036c2c81716cd0166eed67a45c9ef3f81607c3"
    hash4       = "4170edc38601b30ac37c9e43a569e4e01000505e73d89702266efb685dc6a8ac"
    hash5       = "6a11e3d64ee2711e84433d2b8035ce0dafbcffa760c2026e3cfe9ba310008f90"
    hash6       = "0fa3791b48292bf705ed06d701118840e9c87ae1f9ac323fe09b8ad04cedc171"
    hash7       = "f215df78f73f84c8424edec81b4a9e43c0b766f9010caf095301b900f03214fb"
    hash8       = "e4cfca41d64bbf1a0959643523d4734a108bc3ecf6147c83f60db030586c6f25"
    hash9       = "f5e85f2791984d17e00bdb2b7163597d52bf88d9da5a0caedc977a31026ee9f7"
    hash10      = "6a56bdeaf1decad9c4fa4ee5ac7e377d80dfd12601d1317d02f12d9d9fb19646"
    hash11      = "033421645eb5cdfdccc02e470b5304f91fa62121d1e117f1aebca723440cec70"
    hash12      = "921432f56757fdaa414b8b2f729fdd46e41c954a0a96b706c646c1d5ab09e5cb"
    hash13      = "53694193718c2cb2f90fada2d6a11f07ab2c3f8451a0f41ae580b87a142e212e"
    hash14      = "42ec93947d9a157ccd37a3c75c7a06b75fa756fee925b759536deb0993f07a5b"
    hash15      = "7cfaa97d52690e3fa38d039126186e468701b138b24622f48887707d5da022f0"
    hash16      = "520ea6f275b172709ff81bfec4d8a5a9f734ab080b25e7c50bfe2a36800af6e3"

  strings:
    $s1  = "){return \"GGn\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"Fs\";})(),(function f000(){return \"MBb\";})" ascii
    $s2  = "Jm\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"DYs\";})(),(function f000(){return \"Br\";})(),(function" ascii
    $s3  = "ion f000(){return \"Br\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"MBb\";})(),(function f000(){return " ascii
    $s4  = "KXg\";})(),(function f000(){return \"Ml\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"NBs\";})(),(functio" ascii
    $s5  = "function f000(){return \"BQb\";})(),(function f000(){return \"BQb\";})(),(function f000(){return \"Yi\";})(),(function f000(){re" ascii
    $s6  = "),(function f000(){return \"Wy\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"MJq\";})(),(function f000(){" ascii
    $s7  = "urn \"DYx\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"GGn\";})(),(f" ascii
    $s8  = "on f000(){return \"SGs\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"GGn\";})(),(function f000(){return " ascii
    $s9  = " f000(){return \"KIc\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"Mt\";})(),(function f000(){return \"U" ascii
    $s10 = "tion f000(){return \"Mt\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"Wy\";})(),(function f000(){return " ascii
    $s11 = "turn \"DYx\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"Fs\";})(),(function f000(){return \"KIc\";})(),(" ascii
    $s12 = "(){return \"GGn\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"Sv\";})(),(function f000(){return \"RVb\";" ascii
    $s13 = " \"Yi\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"KIc\";})(),(function f000(){return \"KIc\";})(),(fun" ascii
    $s14 = "h\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";})(),(function" ascii
    $s15 = "tion f000(){return \"Um\";})(),(function f000(){return \"DYs\";})(),(function f000(){return \"Nv\";})(),(function f000(){return " ascii
    $s16 = "{return \"GGn\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"MMz\";})(),(function f000(){return \"DAp\";})" ascii
    $s17 = "eturn \"Yz\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"YTp\";})(),(function f000(){return \"Br\";})()," ascii
    $s18 = "Iq\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";})(),(functio" ascii
    $s19 = "000(){return \"GGn\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"SGs\";})(),(function f000(){return \"ZGq" ascii
    $s20 = "unction f000(){return \"GGn\";})(),(function f000(){return \"IAa\";})(),(function f000(){return \"PTi\";})(),(function f000(){re" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}