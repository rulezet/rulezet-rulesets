rule TTP_XOR_QUAD_CurrentVersionRun_eba8 {
  strings:
    $key_eba8 = { b8 c7 [2] 9c c9 [2] b7 e5 [2] 99 c7 [2] 8d dc [2] 82 c6 [2] 9c db [2] 9e da [2] 85 dc [2] 99 db [2] 85 f4 }

  condition:
    any of them
}