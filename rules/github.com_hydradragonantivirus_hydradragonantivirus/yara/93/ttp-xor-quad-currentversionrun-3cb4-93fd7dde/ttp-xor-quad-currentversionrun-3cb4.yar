rule TTP_XOR_QUAD_CurrentVersionRun_3cb4 {
  strings:
    $key_3cb4 = { 6f db [2] 4b d5 [2] 60 f9 [2] 4e db [2] 5a c0 [2] 55 da [2] 4b c7 [2] 49 c6 [2] 52 c0 [2] 4e c7 [2] 52 e8 }

  condition:
    any of them
}