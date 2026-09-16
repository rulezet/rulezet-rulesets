rule TTP_XOR_QUAD_CurrentVersionRun_56ec {
  strings:
    $key_56ec = { 05 83 [2] 21 8d [2] 0a a1 [2] 24 83 [2] 30 98 [2] 3f 82 [2] 21 9f [2] 23 9e [2] 38 98 [2] 24 9f [2] 38 b0 }

  condition:
    any of them
}