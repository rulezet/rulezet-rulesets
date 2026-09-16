rule TTP_XOR_QUAD_CurrentVersionRun_68a8 {
  strings:
    $key_68a8 = { 3b c7 [2] 1f c9 [2] 34 e5 [2] 1a c7 [2] 0e dc [2] 01 c6 [2] 1f db [2] 1d da [2] 06 dc [2] 1a db [2] 06 f4 }

  condition:
    any of them
}