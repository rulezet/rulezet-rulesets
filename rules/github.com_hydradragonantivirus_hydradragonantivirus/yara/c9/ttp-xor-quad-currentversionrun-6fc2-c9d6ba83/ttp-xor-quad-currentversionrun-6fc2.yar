rule TTP_XOR_QUAD_CurrentVersionRun_6fc2 {
  strings:
    $key_6fc2 = { 3c ad [2] 18 a3 [2] 33 8f [2] 1d ad [2] 09 b6 [2] 06 ac [2] 18 b1 [2] 1a b0 [2] 01 b6 [2] 1d b1 [2] 01 9e }

  condition:
    any of them
}