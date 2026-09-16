rule TTP_XOR_QUAD_CurrentVersionRun_6796 {
  strings:
    $key_6796 = { 34 f9 [2] 10 f7 [2] 3b db [2] 15 f9 [2] 01 e2 [2] 0e f8 [2] 10 e5 [2] 12 e4 [2] 09 e2 [2] 15 e5 [2] 09 ca }

  condition:
    any of them
}