rule TTP_XOR_QUAD_CurrentVersionRun_5187 {
  strings:
    $key_5187 = { 02 e8 [2] 26 e6 [2] 0d ca [2] 23 e8 [2] 37 f3 [2] 38 e9 [2] 26 f4 [2] 24 f5 [2] 3f f3 [2] 23 f4 [2] 3f db }

  condition:
    any of them
}