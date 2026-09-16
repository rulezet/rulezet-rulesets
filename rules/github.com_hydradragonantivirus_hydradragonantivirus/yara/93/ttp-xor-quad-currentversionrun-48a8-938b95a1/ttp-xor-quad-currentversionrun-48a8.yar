rule TTP_XOR_QUAD_CurrentVersionRun_48a8 {
  strings:
    $key_48a8 = { 1b c7 [2] 3f c9 [2] 14 e5 [2] 3a c7 [2] 2e dc [2] 21 c6 [2] 3f db [2] 3d da [2] 26 dc [2] 3a db [2] 26 f4 }

  condition:
    any of them
}