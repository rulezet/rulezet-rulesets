rule TTP_XOR_QUAD_CurrentVersionRun_cda9 {
  strings:
    $key_cda9 = { 9e c6 [2] ba c8 [2] 91 e4 [2] bf c6 [2] ab dd [2] a4 c7 [2] ba da [2] b8 db [2] a3 dd [2] bf da [2] a3 f5 }

  condition:
    any of them
}