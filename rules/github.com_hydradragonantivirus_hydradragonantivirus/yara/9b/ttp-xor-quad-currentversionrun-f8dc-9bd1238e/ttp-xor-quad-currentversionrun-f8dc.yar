rule TTP_XOR_QUAD_CurrentVersionRun_f8dc {
  strings:
    $key_f8dc = { ab b3 [2] 8f bd [2] a4 91 [2] 8a b3 [2] 9e a8 [2] 91 b2 [2] 8f af [2] 8d ae [2] 96 a8 [2] 8a af [2] 96 80 }

  condition:
    any of them
}