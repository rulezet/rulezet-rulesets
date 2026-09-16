rule TTP_XOR_QUAD_CurrentVersionRun_7eb5 {
  strings:
    $key_7eb5 = { 2d da [2] 09 d4 [2] 22 f8 [2] 0c da [2] 18 c1 [2] 17 db [2] 09 c6 [2] 0b c7 [2] 10 c1 [2] 0c c6 [2] 10 e9 }

  condition:
    any of them
}