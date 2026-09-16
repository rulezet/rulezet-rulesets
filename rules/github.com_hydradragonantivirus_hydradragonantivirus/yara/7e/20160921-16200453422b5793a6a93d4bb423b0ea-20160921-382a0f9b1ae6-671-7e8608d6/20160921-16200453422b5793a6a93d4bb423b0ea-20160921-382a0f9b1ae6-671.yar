rule _20160921_16200453422b5793a6a93d4bb423b0ea_20160921_382a0f9b1ae6_671 {
  meta:
    description = "datamaliciousorder - from files 20160921_16200453422b5793a6a93d4bb423b0ea.js, 20160921_382a0f9b1ae693f8ade627fd2d6a8b52.js, 20160921_4787695fef4453a16be881bbe0f96c1a.js, 20160921_54325d6949c5c03d42a42e11b24dee5c.js, 20160921_5f0fd6cffcc723799fdcc54a3c2a7ba5.js, 20160921_60c26fdfafa2666b92246aea46e32175.js, 20160921_6748b4ad3c83a7c4aeacfc0817a81797.js, 20160921_cdeac57ac549120611856c7af0c490f6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d968eb9bb2807e5889794bf130036c2c81716cd0166eed67a45c9ef3f81607c3"
    hash2       = "4170edc38601b30ac37c9e43a569e4e01000505e73d89702266efb685dc6a8ac"
    hash3       = "6a11e3d64ee2711e84433d2b8035ce0dafbcffa760c2026e3cfe9ba310008f90"
    hash4       = "0fa3791b48292bf705ed06d701118840e9c87ae1f9ac323fe09b8ad04cedc171"
    hash5       = "f215df78f73f84c8424edec81b4a9e43c0b766f9010caf095301b900f03214fb"
    hash6       = "e4cfca41d64bbf1a0959643523d4734a108bc3ecf6147c83f60db030586c6f25"
    hash7       = "f5e85f2791984d17e00bdb2b7163597d52bf88d9da5a0caedc977a31026ee9f7"
    hash8       = "53694193718c2cb2f90fada2d6a11f07ab2c3f8451a0f41ae580b87a142e212e"

  strings:
    $s1  = "f000(){return \"Qa\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"BMj\";})(),(function f000(){return \"GG" ascii
    $s2  = "ction f000(){return \"RVb\";})(),(function f000(){return \"NYh\";})(),(function f000(){return \"Oe\";})(),(function f000(){retur" ascii
    $s3  = "n\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"IAa\";})(),(function f000(){return \"IPu\";})(),(functio" ascii
    $s4  = "turn \"Ml\";})(),(function f000(){return \"YTp\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"GGn\";})(),(" ascii
    $s5  = "WIj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"DAp\";})(),(functi" ascii
    $s6  = "00(){return \"GGn\";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"GGn\"" ascii
    $s7  = "(function f000(){return \"GGn\";})(),(function f000(){return \"IAa\";})(),(function f000(){return \"NBs\";})(),(function f000(){" ascii
    $s8  = " f000(){return \"GGn\";})(),(function f000(){return \"Tb\";})(),(function f000(){return \"Nx\";})(),(function f000(){return \"GG" ascii
    $s9  = "00(){return \"Br\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"Br\";}" ascii
    $s10 = "function f000(){return \"Sq\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"GGn\";})(),(function f000(){re" ascii
    $s11 = "{return \"DAp\";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"GGn\";})" ascii
    $s12 = "on f000(){return \"RVb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";})(),(function f000(){return " ascii
    $s13 = "ion f000(){return \"YTp\";})(),(function f000(){return \"Mt\";})(),(function f000(){return \"Br\";})(),(function f000(){return " ascii
    $s14 = "Ii\";})(),(function f000(){return \"RLk\";})(),(function f000(){return \"NBs\";})(),(function f000(){return \"Lp\";})(),(functio" ascii
    $s15 = "0(){return \"GGn\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"Wy\";" ascii
    $s16 = "){return \"Br\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"Oe\";})" ascii
    $s17 = "rn \"GGn\";})(),(function f000(){return \"MMz\";})(),(function f000(){return \"DNa\";})(),(function f000(){return \"RVb\";})(),(" ascii
    $s18 = "000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"MBb" ascii
    $s19 = "return \"GGn\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return \"DYx\";})(" ascii
    $s20 = "(){return \"ZIi\";})(),(function f000(){return \"Ml\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"GGn\";}" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}