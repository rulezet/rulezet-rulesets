rule TTP_XOR_QUAD_CurrentVersionRun_58a8 {
  strings:
    $key_58a8 = { 0b c7 [2] 2f c9 [2] 04 e5 [2] 2a c7 [2] 3e dc [2] 31 c6 [2] 2f db [2] 2d da [2] 36 dc [2] 2a db [2] 36 f4 }

  condition:
    any of them
}