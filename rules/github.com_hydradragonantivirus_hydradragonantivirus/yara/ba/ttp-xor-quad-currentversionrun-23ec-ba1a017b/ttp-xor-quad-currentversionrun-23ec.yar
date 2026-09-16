rule TTP_XOR_QUAD_CurrentVersionRun_23ec {
  strings:
    $key_23ec = { 70 83 [2] 54 8d [2] 7f a1 [2] 51 83 [2] 45 98 [2] 4a 82 [2] 54 9f [2] 56 9e [2] 4d 98 [2] 51 9f [2] 4d b0 }

  condition:
    any of them
}