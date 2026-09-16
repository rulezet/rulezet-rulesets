rule TTP_XOR_QUAD_CurrentVersionRun_5dc2 {
  strings:
    $key_5dc2 = { 0e ad [2] 2a a3 [2] 01 8f [2] 2f ad [2] 3b b6 [2] 34 ac [2] 2a b1 [2] 28 b0 [2] 33 b6 [2] 2f b1 [2] 33 9e }

  condition:
    any of them
}