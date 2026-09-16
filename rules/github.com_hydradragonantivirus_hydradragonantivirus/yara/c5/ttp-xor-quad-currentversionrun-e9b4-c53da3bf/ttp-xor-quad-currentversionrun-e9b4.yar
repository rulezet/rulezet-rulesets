rule TTP_XOR_QUAD_CurrentVersionRun_e9b4 {
  strings:
    $key_e9b4 = { ba db [2] 9e d5 [2] b5 f9 [2] 9b db [2] 8f c0 [2] 80 da [2] 9e c7 [2] 9c c6 [2] 87 c0 [2] 9b c7 [2] 87 e8 }

  condition:
    any of them
}