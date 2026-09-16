rule TTP_XOR_QUAD_CurrentVersionRun_08a8 {
  strings:
    $key_08a8 = { 5b c7 [2] 7f c9 [2] 54 e5 [2] 7a c7 [2] 6e dc [2] 61 c6 [2] 7f db [2] 7d da [2] 66 dc [2] 7a db [2] 66 f4 }

  condition:
    any of them
}