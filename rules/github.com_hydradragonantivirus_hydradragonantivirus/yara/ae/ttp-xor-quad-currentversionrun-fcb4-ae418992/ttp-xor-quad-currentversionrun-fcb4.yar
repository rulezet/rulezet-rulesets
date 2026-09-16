rule TTP_XOR_QUAD_CurrentVersionRun_fcb4 {
  strings:
    $key_fcb4 = { af db [2] 8b d5 [2] a0 f9 [2] 8e db [2] 9a c0 [2] 95 da [2] 8b c7 [2] 89 c6 [2] 92 c0 [2] 8e c7 [2] 92 e8 }

  condition:
    any of them
}