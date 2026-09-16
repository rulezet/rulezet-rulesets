rule TTP_XOR_QUAD_CurrentVersionRun_f8c5 {
  strings:
    $key_f8c5 = { ab aa [2] 8f a4 [2] a4 88 [2] 8a aa [2] 9e b1 [2] 91 ab [2] 8f b6 [2] 8d b7 [2] 96 b1 [2] 8a b6 [2] 96 99 }

  condition:
    any of them
}