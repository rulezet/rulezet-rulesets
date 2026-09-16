rule TTP_XOR_QUAD_CurrentVersionRun_19a8 {
  strings:
    $key_19a8 = { 4a c7 [2] 6e c9 [2] 45 e5 [2] 6b c7 [2] 7f dc [2] 70 c6 [2] 6e db [2] 6c da [2] 77 dc [2] 6b db [2] 77 f4 }

  condition:
    any of them
}