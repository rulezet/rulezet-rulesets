rule TTP_XOR_QUAD_CurrentVersionRun_1396 {
  strings:
    $key_1396 = { 40 f9 [2] 64 f7 [2] 4f db [2] 61 f9 [2] 75 e2 [2] 7a f8 [2] 64 e5 [2] 66 e4 [2] 7d e2 [2] 61 e5 [2] 7d ca }

  condition:
    any of them
}