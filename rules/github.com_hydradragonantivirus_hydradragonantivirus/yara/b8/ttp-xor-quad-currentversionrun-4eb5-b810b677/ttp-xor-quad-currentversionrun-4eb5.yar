rule TTP_XOR_QUAD_CurrentVersionRun_4eb5 {
  strings:
    $key_4eb5 = { 1d da [2] 39 d4 [2] 12 f8 [2] 3c da [2] 28 c1 [2] 27 db [2] 39 c6 [2] 3b c7 [2] 20 c1 [2] 3c c6 [2] 20 e9 }

  condition:
    any of them
}