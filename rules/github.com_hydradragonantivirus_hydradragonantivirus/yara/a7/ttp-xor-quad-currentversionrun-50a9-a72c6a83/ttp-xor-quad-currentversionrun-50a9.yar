rule TTP_XOR_QUAD_CurrentVersionRun_50a9 {
  strings:
    $key_50a9 = { 03 c6 [2] 27 c8 [2] 0c e4 [2] 22 c6 [2] 36 dd [2] 39 c7 [2] 27 da [2] 25 db [2] 3e dd [2] 22 da [2] 3e f5 }

  condition:
    any of them
}