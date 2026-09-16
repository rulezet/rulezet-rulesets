rule TTP_XOR_QUAD_CurrentVersionRun_4cb4 {
  strings:
    $key_4cb4 = { 1f db [2] 3b d5 [2] 10 f9 [2] 3e db [2] 2a c0 [2] 25 da [2] 3b c7 [2] 39 c6 [2] 22 c0 [2] 3e c7 [2] 22 e8 }

  condition:
    any of them
}