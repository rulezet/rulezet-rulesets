rule TTP_XOR_QUAD_CurrentVersionRun_39dc {
  strings:
    $key_39dc = { 6a b3 [2] 4e bd [2] 65 91 [2] 4b b3 [2] 5f a8 [2] 50 b2 [2] 4e af [2] 4c ae [2] 57 a8 [2] 4b af [2] 57 80 }

  condition:
    any of them
}