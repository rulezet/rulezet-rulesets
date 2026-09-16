rule TTP_XOR_QUAD_CurrentVersionRun_5096 {
  strings:
    $key_5096 = { 03 f9 [2] 27 f7 [2] 0c db [2] 22 f9 [2] 36 e2 [2] 39 f8 [2] 27 e5 [2] 25 e4 [2] 3e e2 [2] 22 e5 [2] 3e ca }

  condition:
    any of them
}