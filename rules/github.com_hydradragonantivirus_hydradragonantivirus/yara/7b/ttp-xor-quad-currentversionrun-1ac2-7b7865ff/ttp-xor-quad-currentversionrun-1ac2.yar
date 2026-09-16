rule TTP_XOR_QUAD_CurrentVersionRun_1ac2 {
  strings:
    $key_1ac2 = { 49 ad [2] 6d a3 [2] 46 8f [2] 68 ad [2] 7c b6 [2] 73 ac [2] 6d b1 [2] 6f b0 [2] 74 b6 [2] 68 b1 [2] 74 9e }

  condition:
    any of them
}