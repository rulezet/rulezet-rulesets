rule TTP_XOR_QUAD_CurrentVersionRun_13ec {
  strings:
    $key_13ec = { 40 83 [2] 64 8d [2] 4f a1 [2] 61 83 [2] 75 98 [2] 7a 82 [2] 64 9f [2] 66 9e [2] 7d 98 [2] 61 9f [2] 7d b0 }

  condition:
    any of them
}