rule TTP_XOR_QUAD_CurrentVersionRun_7cb4 {
  strings:
    $key_7cb4 = { 2f db [2] 0b d5 [2] 20 f9 [2] 0e db [2] 1a c0 [2] 15 da [2] 0b c7 [2] 09 c6 [2] 12 c0 [2] 0e c7 [2] 12 e8 }

  condition:
    any of them
}