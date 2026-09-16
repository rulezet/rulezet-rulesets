rule _20160921_2a4c1d98d0b8022ca5527a8e6d96e6e7_20160921_80e6ac924bf1_4796 {
  meta:
    description = "datamaliciousorder - from files 20160921_2a4c1d98d0b8022ca5527a8e6d96e6e7.js, 20160921_80e6ac924bf190eef40e43ba5d57f11b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "65be7c1c5efef8255d7094d95251c12de72303024061cff2152d54a244a049f0"
    hash2       = "e240b858e2fac9be9a3fc0f8611c4c05e6f217dd1e13ac43649aa6d7597ee450"

  strings:
    $s1 = "),(function f000(){return \"OUx\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"TRc\";})(),(function f000(" ascii
    $s2 = "t\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"TRc\";})(),(function" ascii
    $s3 = "n \"ZFe\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"Do\";})(),(fun" ascii
    $s4 = "000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"SEo" ascii
    $s5 = "{return \"DAp\";})(),(function f000(){return \"MMz\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"Vu\";})(" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}