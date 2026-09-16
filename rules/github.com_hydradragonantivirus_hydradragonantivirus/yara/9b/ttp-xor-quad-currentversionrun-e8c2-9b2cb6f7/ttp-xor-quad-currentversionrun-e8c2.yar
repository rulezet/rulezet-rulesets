rule TTP_XOR_QUAD_CurrentVersionRun_e8c2 {
  strings:
    $key_e8c2 = { bb ad [2] 9f a3 [2] b4 8f [2] 9a ad [2] 8e b6 [2] 81 ac [2] 9f b1 [2] 9d b0 [2] 86 b6 [2] 9a b1 [2] 86 9e }

  condition:
    any of them
}