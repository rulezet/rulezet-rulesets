rule TTP_XOR_QUAD_CurrentVersionRun_01d5 {
  strings:
    $key_01d5 = { 52 ba [2] 76 b4 [2] 5d 98 [2] 73 ba [2] 67 a1 [2] 68 bb [2] 76 a6 [2] 74 a7 [2] 6f a1 [2] 73 a6 [2] 6f 89 }

  condition:
    any of them
}