rule TTP_XOR_QUAD_CurrentVersionRun_68c5 {
  strings:
    $key_68c5 = { 3b aa [2] 1f a4 [2] 34 88 [2] 1a aa [2] 0e b1 [2] 01 ab [2] 1f b6 [2] 1d b7 [2] 06 b1 [2] 1a b6 [2] 06 99 }

  condition:
    any of them
}