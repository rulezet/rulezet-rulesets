rule TTP_XOR_QUAD_CurrentVersionRun_4bc2 {
  strings:
    $key_4bc2 = { 18 ad [2] 3c a3 [2] 17 8f [2] 39 ad [2] 2d b6 [2] 22 ac [2] 3c b1 [2] 3e b0 [2] 25 b6 [2] 39 b1 [2] 25 9e }

  condition:
    any of them
}