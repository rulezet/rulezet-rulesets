rule TTP_XOR_QUAD_CurrentVersionRun_70a9 {
  strings:
    $key_70a9 = { 23 c6 [2] 07 c8 [2] 2c e4 [2] 02 c6 [2] 16 dd [2] 19 c7 [2] 07 da [2] 05 db [2] 1e dd [2] 02 da [2] 1e f5 }

  condition:
    any of them
}