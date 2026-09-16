rule TTP_XOR_QUAD_CurrentVersionRun_2096 {
  strings:
    $key_2096 = { 73 f9 [2] 57 f7 [2] 7c db [2] 52 f9 [2] 46 e2 [2] 49 f8 [2] 57 e5 [2] 55 e4 [2] 4e e2 [2] 52 e5 [2] 4e ca }

  condition:
    any of them
}