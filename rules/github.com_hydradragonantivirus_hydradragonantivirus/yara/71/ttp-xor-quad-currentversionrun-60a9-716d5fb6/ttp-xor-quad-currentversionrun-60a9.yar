rule TTP_XOR_QUAD_CurrentVersionRun_60a9 {
  strings:
    $key_60a9 = { 33 c6 [2] 17 c8 [2] 3c e4 [2] 12 c6 [2] 06 dd [2] 09 c7 [2] 17 da [2] 15 db [2] 0e dd [2] 12 da [2] 0e f5 }

  condition:
    any of them
}