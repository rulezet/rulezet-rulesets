rule TTP_XOR_QUAD_CurrentVersionRun_3fb4 {
  strings:
    $key_3fb4 = { 6c db [2] 48 d5 [2] 63 f9 [2] 4d db [2] 59 c0 [2] 56 da [2] 48 c7 [2] 4a c6 [2] 51 c0 [2] 4d c7 [2] 51 e8 }

  condition:
    any of them
}