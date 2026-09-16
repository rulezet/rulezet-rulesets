rule TTP_XOR_QUAD_CurrentVersionRun_7db4 {
  strings:
    $key_7db4 = { 2e db [2] 0a d5 [2] 21 f9 [2] 0f db [2] 1b c0 [2] 14 da [2] 0a c7 [2] 08 c6 [2] 13 c0 [2] 0f c7 [2] 13 e8 }

  condition:
    any of them
}