rule TTP_XOR_QUAD_CurrentVersionRun_0496 {
  strings:
    $key_0496 = { 57 f9 [2] 73 f7 [2] 58 db [2] 76 f9 [2] 62 e2 [2] 6d f8 [2] 73 e5 [2] 71 e4 [2] 6a e2 [2] 76 e5 [2] 6a ca }

  condition:
    any of them
}