rule TTP_XOR_QUAD_CurrentVersionRun_2db4 {
  strings:
    $key_2db4 = { 7e db [2] 5a d5 [2] 71 f9 [2] 5f db [2] 4b c0 [2] 44 da [2] 5a c7 [2] 58 c6 [2] 43 c0 [2] 5f c7 [2] 43 e8 }

  condition:
    any of them
}