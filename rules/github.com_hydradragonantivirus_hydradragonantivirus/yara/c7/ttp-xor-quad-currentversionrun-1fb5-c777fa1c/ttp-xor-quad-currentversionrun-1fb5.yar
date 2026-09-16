rule TTP_XOR_QUAD_CurrentVersionRun_1fb5 {
  strings:
    $key_1fb5 = { 4c da [2] 68 d4 [2] 43 f8 [2] 6d da [2] 79 c1 [2] 76 db [2] 68 c6 [2] 6a c7 [2] 71 c1 [2] 6d c6 [2] 71 e9 }

  condition:
    any of them
}