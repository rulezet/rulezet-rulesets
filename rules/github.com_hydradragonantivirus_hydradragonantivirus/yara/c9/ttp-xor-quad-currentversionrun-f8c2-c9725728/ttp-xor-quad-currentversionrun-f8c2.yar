rule TTP_XOR_QUAD_CurrentVersionRun_f8c2 {
  strings:
    $key_f8c2 = { ab ad [2] 8f a3 [2] a4 8f [2] 8a ad [2] 9e b6 [2] 91 ac [2] 8f b1 [2] 8d b0 [2] 96 b6 [2] 8a b1 [2] 96 9e }

  condition:
    any of them
}