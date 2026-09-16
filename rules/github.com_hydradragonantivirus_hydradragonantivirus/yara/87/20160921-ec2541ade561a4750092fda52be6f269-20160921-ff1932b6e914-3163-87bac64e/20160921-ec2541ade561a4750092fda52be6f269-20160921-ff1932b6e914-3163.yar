rule _20160921_ec2541ade561a4750092fda52be6f269_20160921_ff1932b6e914_3163 {
  meta:
    description = "datamaliciousorder - from files 20160921_ec2541ade561a4750092fda52be6f269.js, 20160921_ff1932b6e91481dd80ff6251296b57fe.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1db7ed5a240fde30e4fca12eca866b9b96b56836ae50ea4c0fcf2d28b08be3b5"
    hash2       = "07e5271d8517f89575dc2737fae5e8da89c7f2f25cd40c68e183d826da6b2bf0"

  strings:
    $s1 = "f000(){return \"GGn\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Yi" ascii
    $s2 = "n f000(){return \"Rh\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"M" ascii
    $s3 = "rn \"Wy\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";})(),(f" ascii
    $s4 = "urn \"GGn\";})(),(function f000(){return \"SEo\";})(),(function f000(){return \"Km\";})(),(function f000(){return \"GGn\";})(),(" ascii
    $s5 = "ction f000(){return \"DYx\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"GGn\";})(),(function f000(){retu" ascii
    $s6 = "(function f000(){return \"UEg\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"Br\";})(),(function f000(){re" ascii
    $s7 = "BQb\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"Br\";})(),(functio" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}