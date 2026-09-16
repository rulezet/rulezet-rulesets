rule TTP_XOR_QUAD_CurrentVersionRun_1dc2 {
  strings:
    $key_1dc2 = { 4e ad [2] 6a a3 [2] 41 8f [2] 6f ad [2] 7b b6 [2] 74 ac [2] 6a b1 [2] 68 b0 [2] 73 b6 [2] 6f b1 [2] 73 9e }

  condition:
    any of them
}