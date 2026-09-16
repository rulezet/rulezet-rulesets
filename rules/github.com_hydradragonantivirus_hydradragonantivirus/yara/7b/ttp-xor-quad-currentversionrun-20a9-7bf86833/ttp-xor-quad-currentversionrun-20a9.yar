rule TTP_XOR_QUAD_CurrentVersionRun_20a9 {
  strings:
    $key_20a9 = { 73 c6 [2] 57 c8 [2] 7c e4 [2] 52 c6 [2] 46 dd [2] 49 c7 [2] 57 da [2] 55 db [2] 4e dd [2] 52 da [2] 4e f5 }

  condition:
    any of them
}