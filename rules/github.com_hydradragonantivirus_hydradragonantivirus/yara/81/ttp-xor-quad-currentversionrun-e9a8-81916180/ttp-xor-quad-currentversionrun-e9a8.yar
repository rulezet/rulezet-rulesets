rule TTP_XOR_QUAD_CurrentVersionRun_e9a8 {
  strings:
    $key_e9a8 = { ba c7 [2] 9e c9 [2] b5 e5 [2] 9b c7 [2] 8f dc [2] 80 c6 [2] 9e db [2] 9c da [2] 87 dc [2] 9b db [2] 87 f4 }

  condition:
    any of them
}