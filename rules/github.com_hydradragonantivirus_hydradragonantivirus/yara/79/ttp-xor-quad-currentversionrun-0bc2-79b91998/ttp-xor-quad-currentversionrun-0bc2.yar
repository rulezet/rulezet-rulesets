rule TTP_XOR_QUAD_CurrentVersionRun_0bc2 {
  strings:
    $key_0bc2 = { 58 ad [2] 7c a3 [2] 57 8f [2] 79 ad [2] 6d b6 [2] 62 ac [2] 7c b1 [2] 7e b0 [2] 65 b6 [2] 79 b1 [2] 65 9e }

  condition:
    any of them
}