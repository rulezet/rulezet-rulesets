rule TTP_XOR_QUAD_CurrentVersionRun_431d {
  strings:
    $key_431d = { 10 72 [2] 34 7c [2] 1f 50 [2] 31 72 [2] 25 69 [2] 2a 73 [2] 34 6e [2] 36 6f [2] 2d 69 [2] 31 6e [2] 2d 41 }

  condition:
    any of them
}