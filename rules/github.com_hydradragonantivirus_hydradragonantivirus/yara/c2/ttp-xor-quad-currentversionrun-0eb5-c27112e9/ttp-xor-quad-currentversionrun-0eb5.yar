rule TTP_XOR_QUAD_CurrentVersionRun_0eb5 {
  strings:
    $key_0eb5 = { 5d da [2] 79 d4 [2] 52 f8 [2] 7c da [2] 68 c1 [2] 67 db [2] 79 c6 [2] 7b c7 [2] 60 c1 [2] 7c c6 [2] 60 e9 }

  condition:
    any of them
}