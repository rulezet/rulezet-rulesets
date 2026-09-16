rule _20160921_0550bef558fba79f944112d34861e4ec_20160921_3a89132c2088_2640 {
  meta:
    description = "datamaliciousorder - from files 20160921_0550bef558fba79f944112d34861e4ec.js, 20160921_3a89132c20887c3360a3708984b884fb.js, 20160921_4b85b9629682d9cbd379b3404bd09eb1.js, 20160921_54ac484c468ac2ca7fe6c7210ca717bb.js, 20160921_c05dd34a09358454c56b9c248f1d0304.js, 20160921_c54afc417f4f2e6afc93a834c28784f2.js, 20160921_c9a772728edf4eeff48c1aea32c00a13.js, 20160921_d7492227e681b1689bfc5442a91a169e.js, 20160921_e432cba10cde369693d6b125dda112c7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7cc46901b4b691df366f68f1812df531215964f5150686b06997f1f49b536a1c"
    hash2       = "9687ad9b2ded14e00c5b17393de82acd451266863fb217fc6647e1add112f2fd"
    hash3       = "43de7c579d15cb70a31da759a94145ff9a831b9bf0e5ff93ae38b5064231b62f"
    hash4       = "5b883334540a4216b3582d1f2fa0a27f21b9c64a87944c8e58d9fab0f609eef3"
    hash5       = "e330ec83e6ac964ffd679e6589494a6108e1995f570c539dee7b1be30953f8a3"
    hash6       = "20ec6b05e6f9287e0487d83e2fe14d9d0ca6d013f0a0ee7abade9f2b0b6268d5"
    hash7       = "76f52cefe2f1cf5954919532ecd1ec4c5c9072cb4edc435169d570baa9894ed9"
    hash8       = "63aa129680edf69c72e8f077be5e8562f041fa0b0c7e63a8a9b219c23749b135"
    hash9       = "0f0aa2d80d649fb44a67c6ec77b95eb26709057f543ca215edf15a9bcc4bae4b"

  strings:
    $s1 = "\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"Wy\";})(),(function f" ascii
    $s2 = " \"Mc\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"YTp\";})(),(func" ascii
    $s3 = "ction f000(){return \"Tn\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"TKp\";})(),(function f000(){retur" ascii
    $s4 = "0(){return \"Nv\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"Lo\";})(),(function f000(){return \"Iq\";}" ascii
    $s5 = "eturn \"MBb\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"Iq\";})(),(" ascii
    $s6 = " f000(){return \"TKp\";})(),(function f000(){return \"IPu\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"" ascii
    $s7 = "),(function f000(){return \"Ml\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"NBs\";})(),(function f000(){" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}