rule TTP_XOR_QUAD_CurrentVersionRun_78c5 {
  strings:
    $key_78c5 = { 2b aa [2] 0f a4 [2] 24 88 [2] 0a aa [2] 1e b1 [2] 11 ab [2] 0f b6 [2] 0d b7 [2] 16 b1 [2] 0a b6 [2] 16 99 }

  condition:
    any of them
}