rule _20160921_0550bef558fba79f944112d34861e4ec_20160921_27fb26e7e153_4230 {
  meta:
    description = "datamaliciousorder - from files 20160921_0550bef558fba79f944112d34861e4ec.js, 20160921_27fb26e7e153703634890a2f9e37ef7b.js, 20160921_cff7808833d9e819d4a4f10450848a81.js, 20160921_e432cba10cde369693d6b125dda112c7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7cc46901b4b691df366f68f1812df531215964f5150686b06997f1f49b536a1c"
    hash2       = "867c0b561ad28bc562227169c7a21fbf367232ec2d2454d4bd819e1a42cc1b62"
    hash3       = "542990d73514ef4ff7fb1540013f789833830036dc9c9c2ad8c49c1bdabb1f2a"
    hash4       = "0f0aa2d80d649fb44a67c6ec77b95eb26709057f543ca215edf15a9bcc4bae4b"

  strings:
    $s1 = "n \"Yv\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Sj0\";})(),(fun" ascii
    $s2 = "00(){return \"WIj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"RLk\";})(),(function f000(){return \"Wb" ascii
    $s3 = ",(function f000(){return \"GGn\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"ZFe\";})(),(function f000()" ascii
    $s4 = "){return \"Tn\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"OUx\";}" ascii
    $s5 = "ction f000(){return \"TRc\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"KZr\";})(),(function f000(){retur" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}