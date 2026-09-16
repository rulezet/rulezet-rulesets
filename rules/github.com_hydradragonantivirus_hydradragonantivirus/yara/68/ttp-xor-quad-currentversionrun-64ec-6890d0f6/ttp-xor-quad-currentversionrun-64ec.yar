rule TTP_XOR_QUAD_CurrentVersionRun_64ec {
  strings:
    $key_64ec = { 37 83 [2] 13 8d [2] 38 a1 [2] 16 83 [2] 02 98 [2] 0d 82 [2] 13 9f [2] 11 9e [2] 0a 98 [2] 16 9f [2] 0a b0 }

  condition:
    any of them
}