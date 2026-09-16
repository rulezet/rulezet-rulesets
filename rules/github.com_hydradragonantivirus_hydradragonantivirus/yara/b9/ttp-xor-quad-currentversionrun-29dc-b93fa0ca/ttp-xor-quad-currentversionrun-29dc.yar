rule TTP_XOR_QUAD_CurrentVersionRun_29dc {
  strings:
    $key_29dc = { 7a b3 [2] 5e bd [2] 75 91 [2] 5b b3 [2] 4f a8 [2] 40 b2 [2] 5e af [2] 5c ae [2] 47 a8 [2] 5b af [2] 47 80 }

  condition:
    any of them
}