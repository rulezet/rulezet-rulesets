rule TTP_XOR_QUAD_CurrentVersionRun_59c2 {
  strings:
    $key_59c2 = { 0a ad [2] 2e a3 [2] 05 8f [2] 2b ad [2] 3f b6 [2] 30 ac [2] 2e b1 [2] 2c b0 [2] 37 b6 [2] 2b b1 [2] 37 9e }

  condition:
    any of them
}