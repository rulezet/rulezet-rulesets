rule TTP_XOR_QUAD_CurrentVersionRun_74ec {
  strings:
    $key_74ec = { 27 83 [2] 03 8d [2] 28 a1 [2] 06 83 [2] 12 98 [2] 1d 82 [2] 03 9f [2] 01 9e [2] 1a 98 [2] 06 9f [2] 1a b0 }

  condition:
    any of them
}