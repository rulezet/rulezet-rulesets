rule TTP_XOR_QUAD_CurrentVersionRun_0187 {
  strings:
    $key_0187 = { 52 e8 [2] 76 e6 [2] 5d ca [2] 73 e8 [2] 67 f3 [2] 68 e9 [2] 76 f4 [2] 74 f5 [2] 6f f3 [2] 73 f4 [2] 6f db }

  condition:
    any of them
}