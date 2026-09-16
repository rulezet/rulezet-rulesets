rule TTP_XOR_QUAD_CurrentVersionRun_58dc {
  strings:
    $key_58dc = { 0b b3 [2] 2f bd [2] 04 91 [2] 2a b3 [2] 3e a8 [2] 31 b2 [2] 2f af [2] 2d ae [2] 36 a8 [2] 2a af [2] 36 80 }

  condition:
    any of them
}