rule TTP_XOR_QUAD_CurrentVersionRun_41ec {
  strings:
    $key_41ec = { 12 83 [2] 36 8d [2] 1d a1 [2] 33 83 [2] 27 98 [2] 28 82 [2] 36 9f [2] 34 9e [2] 2f 98 [2] 33 9f [2] 2f b0 }

  condition:
    any of them
}