rule TTP_XOR_QUAD_CurrentVersionRun_18c2 {
  strings:
    $key_18c2 = { 4b ad [2] 6f a3 [2] 44 8f [2] 6a ad [2] 7e b6 [2] 71 ac [2] 6f b1 [2] 6d b0 [2] 76 b6 [2] 6a b1 [2] 76 9e }

  condition:
    any of them
}