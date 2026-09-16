rule TTP_XOR_QUAD_CurrentVersionRun_58c2 {
  strings:
    $key_58c2 = { 0b ad [2] 2f a3 [2] 04 8f [2] 2a ad [2] 3e b6 [2] 31 ac [2] 2f b1 [2] 2d b0 [2] 36 b6 [2] 2a b1 [2] 36 9e }

  condition:
    any of them
}