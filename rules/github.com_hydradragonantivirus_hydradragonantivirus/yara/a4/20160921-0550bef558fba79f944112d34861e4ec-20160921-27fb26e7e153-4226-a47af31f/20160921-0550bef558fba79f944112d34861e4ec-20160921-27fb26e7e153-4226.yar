rule _20160921_0550bef558fba79f944112d34861e4ec_20160921_27fb26e7e153_4226 {
  meta:
    description = "datamaliciousorder - from files 20160921_0550bef558fba79f944112d34861e4ec.js, 20160921_27fb26e7e153703634890a2f9e37ef7b.js, 20160921_86f41d8c83240a68770674107f15f162.js, 20160921_a1cbb43a1e22a4b1fd63ee1a724173eb.js, 20160921_cff7808833d9e819d4a4f10450848a81.js, 20160921_da7f7f057c35b886425ec822f654da90.js, 20160921_e432cba10cde369693d6b125dda112c7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7cc46901b4b691df366f68f1812df531215964f5150686b06997f1f49b536a1c"
    hash2       = "867c0b561ad28bc562227169c7a21fbf367232ec2d2454d4bd819e1a42cc1b62"
    hash3       = "56a4c0b8742284d9e8907df1b8d73d9c73ee82bc9595e88d869c555afd77312d"
    hash4       = "4154e4928eccd35fa0d42dbefe4a742700d77124216f8b5756b8ef63634071d3"
    hash5       = "542990d73514ef4ff7fb1540013f789833830036dc9c9c2ad8c49c1bdabb1f2a"
    hash6       = "b6935463e925cb13fc2413b3d7559cf8e9f5072c15dc73075977046a3e27e417"
    hash7       = "0f0aa2d80d649fb44a67c6ec77b95eb26709057f543ca215edf15a9bcc4bae4b"

  strings:
    $s1 = "rn \"GGn\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Sq\";})(),(f" ascii
    $s2 = "\"Iq\";})(),(function f000(){return \"BQb\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"QDg\";})(),(funct" ascii
    $s3 = "f000(){return \"UEg\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"Ml\";})(),(function f000(){return \"DN" ascii
    $s4 = ",(function f000(){return \"Oe\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"PTs\";})(),(function f000(){r" ascii
    $s5 = "(){return \"DNa\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"Nx\";})(),(function f000(){return \"DIa\";}" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}