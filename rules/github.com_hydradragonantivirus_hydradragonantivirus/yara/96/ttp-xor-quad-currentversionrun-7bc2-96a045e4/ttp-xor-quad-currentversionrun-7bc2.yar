rule TTP_XOR_QUAD_CurrentVersionRun_7bc2 {
  strings:
    $key_7bc2 = { 28 ad [2] 0c a3 [2] 27 8f [2] 09 ad [2] 1d b6 [2] 12 ac [2] 0c b1 [2] 0e b0 [2] 15 b6 [2] 09 b1 [2] 15 9e }

  condition:
    any of them
}