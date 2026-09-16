rule TTP_XOR_QUAD_CurrentVersionRun_2187 {
  strings:
    $key_2187 = { 72 e8 [2] 56 e6 [2] 7d ca [2] 53 e8 [2] 47 f3 [2] 48 e9 [2] 56 f4 [2] 54 f5 [2] 4f f3 [2] 53 f4 [2] 4f db }

  condition:
    any of them
}