rule TTP_XOR_QUAD_CurrentVersionRun_6396 {
  strings:
    $key_6396 = { 30 f9 [2] 14 f7 [2] 3f db [2] 11 f9 [2] 05 e2 [2] 0a f8 [2] 14 e5 [2] 16 e4 [2] 0d e2 [2] 11 e5 [2] 0d ca }

  condition:
    any of them
}