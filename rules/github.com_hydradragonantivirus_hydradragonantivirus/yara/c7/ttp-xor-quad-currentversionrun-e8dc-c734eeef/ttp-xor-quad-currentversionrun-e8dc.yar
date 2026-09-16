rule TTP_XOR_QUAD_CurrentVersionRun_e8dc {
  strings:
    $key_e8dc = { bb b3 [2] 9f bd [2] b4 91 [2] 9a b3 [2] 8e a8 [2] 81 b2 [2] 9f af [2] 9d ae [2] 86 a8 [2] 9a af [2] 86 80 }

  condition:
    any of them
}