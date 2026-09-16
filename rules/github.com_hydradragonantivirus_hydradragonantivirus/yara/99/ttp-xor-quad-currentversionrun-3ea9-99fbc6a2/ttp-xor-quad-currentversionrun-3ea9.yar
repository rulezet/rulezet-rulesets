rule TTP_XOR_QUAD_CurrentVersionRun_3ea9 {
  strings:
    $key_3ea9 = { 6d c6 [2] 49 c8 [2] 62 e4 [2] 4c c6 [2] 58 dd [2] 57 c7 [2] 49 da [2] 4b db [2] 50 dd [2] 4c da [2] 50 f5 }

  condition:
    any of them
}