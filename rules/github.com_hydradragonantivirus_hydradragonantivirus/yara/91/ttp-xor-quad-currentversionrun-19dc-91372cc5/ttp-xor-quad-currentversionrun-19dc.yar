rule TTP_XOR_QUAD_CurrentVersionRun_19dc {
  strings:
    $key_19dc = { 4a b3 [2] 6e bd [2] 45 91 [2] 6b b3 [2] 7f a8 [2] 70 b2 [2] 6e af [2] 6c ae [2] 77 a8 [2] 6b af [2] 77 80 }

  condition:
    any of them
}