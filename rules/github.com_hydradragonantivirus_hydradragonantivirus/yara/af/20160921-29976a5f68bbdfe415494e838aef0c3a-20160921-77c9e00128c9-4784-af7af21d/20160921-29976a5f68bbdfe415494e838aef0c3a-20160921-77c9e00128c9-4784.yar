rule _20160921_29976a5f68bbdfe415494e838aef0c3a_20160921_77c9e00128c9_4784 {
  meta:
    description = "datamaliciousorder - from files 20160921_29976a5f68bbdfe415494e838aef0c3a.js, 20160921_77c9e00128c9a883c23909fbb2c12569.js, 20160921_e98813a05e661b621a9d4b3a1d6d901f.js, 20160921_ec2541ade561a4750092fda52be6f269.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "218bc62c15296caf93128e0a5e06fde374e19fd4150b6c9b1def4d962554ef39"
    hash2       = "95544bd07dbc8b2550e3a6bb328d49a808c8749bb3ced90cbb8f5f90782625a1"
    hash3       = "5b491479317737dd237b9c5bc10e2831e78ae8bbc9ea6a11e5ef5f5bc6c813f8"
    hash4       = "1db7ed5a240fde30e4fca12eca866b9b96b56836ae50ea4c0fcf2d28b08be3b5"

  strings:
    $s1 = "),(function f000(){return \"YTp\";})(),(function f000(){return \"Mt\";})(),(function f000(){return \"UEg\";})(),(function f000()" ascii
    $s2 = "nction f000(){return \"DIa\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Uo\";})(),(function f000(){retu" ascii
    $s3 = "n \"Wy\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"Oe\";})(),(funct" ascii
    $s4 = "ion f000(){return \"Ml\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"" ascii
    $s5 = "\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"QDg\";})(),(function " ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}