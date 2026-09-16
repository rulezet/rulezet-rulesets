rule TTP_XOR_QUAD_CurrentVersionRun_1096 {
  strings:
    $key_1096 = { 43 f9 [2] 67 f7 [2] 4c db [2] 62 f9 [2] 76 e2 [2] 79 f8 [2] 67 e5 [2] 65 e4 [2] 7e e2 [2] 62 e5 [2] 7e ca }

  condition:
    any of them
}