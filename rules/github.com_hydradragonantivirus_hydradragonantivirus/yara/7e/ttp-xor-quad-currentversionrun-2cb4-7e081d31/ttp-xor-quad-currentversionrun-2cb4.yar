rule TTP_XOR_QUAD_CurrentVersionRun_2cb4 {
  strings:
    $key_2cb4 = { 7f db [2] 5b d5 [2] 70 f9 [2] 5e db [2] 4a c0 [2] 45 da [2] 5b c7 [2] 59 c6 [2] 42 c0 [2] 5e c7 [2] 42 e8 }

  condition:
    any of them
}