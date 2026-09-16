rule TTP_XOR_QUAD_CurrentVersionRun_fca8 {
  strings:
    $key_fca8 = { af c7 [2] 8b c9 [2] a0 e5 [2] 8e c7 [2] 9a dc [2] 95 c6 [2] 8b db [2] 89 da [2] 92 dc [2] 8e db [2] 92 f4 }

  condition:
    any of them
}