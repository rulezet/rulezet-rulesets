rule TTP_XOR_QUAD_CurrentVersionRun_79dc {
  strings:
    $key_79dc = { 2a b3 [2] 0e bd [2] 25 91 [2] 0b b3 [2] 1f a8 [2] 10 b2 [2] 0e af [2] 0c ae [2] 17 a8 [2] 0b af [2] 17 80 }

  condition:
    any of them
}