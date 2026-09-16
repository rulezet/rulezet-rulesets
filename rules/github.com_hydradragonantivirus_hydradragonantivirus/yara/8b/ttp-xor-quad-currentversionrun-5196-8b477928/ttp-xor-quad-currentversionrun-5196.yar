rule TTP_XOR_QUAD_CurrentVersionRun_5196 {
  strings:
    $key_5196 = { 02 f9 [2] 26 f7 [2] 0d db [2] 23 f9 [2] 37 e2 [2] 38 f8 [2] 26 e5 [2] 24 e4 [2] 3f e2 [2] 23 e5 [2] 3f ca }

  condition:
    any of them
}