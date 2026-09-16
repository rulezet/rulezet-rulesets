rule TTP_XOR_QUAD_CurrentVersionRun_7396 {
  strings:
    $key_7396 = { 20 f9 [2] 04 f7 [2] 2f db [2] 01 f9 [2] 15 e2 [2] 1a f8 [2] 04 e5 [2] 06 e4 [2] 1d e2 [2] 01 e5 [2] 1d ca }

  condition:
    any of them
}