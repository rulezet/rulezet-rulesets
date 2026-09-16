rule TTP_XOR_QUAD_CurrentVersionRun_48c2 {
  strings:
    $key_48c2 = { 1b ad [2] 3f a3 [2] 14 8f [2] 3a ad [2] 2e b6 [2] 21 ac [2] 3f b1 [2] 3d b0 [2] 26 b6 [2] 3a b1 [2] 26 9e }

  condition:
    any of them
}