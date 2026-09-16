rule TTP_XOR_QUAD_CurrentVersionRun_6496 {
  strings:
    $key_6496 = { 37 f9 [2] 13 f7 [2] 38 db [2] 16 f9 [2] 02 e2 [2] 0d f8 [2] 13 e5 [2] 11 e4 [2] 0a e2 [2] 16 e5 [2] 0a ca }

  condition:
    any of them
}