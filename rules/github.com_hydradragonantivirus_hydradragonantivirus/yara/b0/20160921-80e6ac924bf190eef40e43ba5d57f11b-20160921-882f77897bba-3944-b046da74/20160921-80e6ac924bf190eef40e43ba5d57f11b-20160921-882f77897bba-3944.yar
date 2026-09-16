rule _20160921_80e6ac924bf190eef40e43ba5d57f11b_20160921_882f77897bba_3944 {
  meta:
    description = "datamaliciousorder - from files 20160921_80e6ac924bf190eef40e43ba5d57f11b.js, 20160921_882f77897bba85afdc56810c29ef4cbb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e240b858e2fac9be9a3fc0f8611c4c05e6f217dd1e13ac43649aa6d7597ee450"
    hash2       = "9e1a86c6dc71a5b10659658c07a01bb1541887750ecf88ab56997c7dbc2d180c"

  strings:
    $s1 = ";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Yi\";})(),(function f00" ascii
    $s2 = ",(function f000(){return \"RPt\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"Vu\";})(),(function f000(){r" ascii
    $s3 = "n \"UEg\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"XTn\";})(),(fu" ascii
    $s4 = "turn \"Do\";})(),(function f000(){return \"MKa\";})(),(function f000(){return \"Ot\";})(),(function f000(){return \"UEg\";})(),(" ascii
    $s5 = "urn \"WIj\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"RPt\";})(),(" ascii
    $s6 = "function f000(){return \"GGn\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"XTn\";})(),(function f000(){re" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}