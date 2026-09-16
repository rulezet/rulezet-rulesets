rule TTP_XOR_QUAD_CurrentVersionRun_4ea9 {
  strings:
    $key_4ea9 = { 1d c6 [2] 39 c8 [2] 12 e4 [2] 3c c6 [2] 28 dd [2] 27 c7 [2] 39 da [2] 3b db [2] 20 dd [2] 3c da [2] 20 f5 }

  condition:
    any of them
}