rule TTP_XOR_QUAD_CurrentVersionRun_28c2 {
  strings:
    $key_28c2 = { 7b ad [2] 5f a3 [2] 74 8f [2] 5a ad [2] 4e b6 [2] 41 ac [2] 5f b1 [2] 5d b0 [2] 46 b6 [2] 5a b1 [2] 46 9e }

  condition:
    any of them
}