rule TTP_XOR_QUAD_CurrentVersionRun_08c5 {
  strings:
    $key_08c5 = { 5b aa [2] 7f a4 [2] 54 88 [2] 7a aa [2] 6e b1 [2] 61 ab [2] 7f b6 [2] 7d b7 [2] 66 b1 [2] 7a b6 [2] 66 99 }

  condition:
    any of them
}