rule TTP_XOR_QUAD_CurrentVersionRun_03ec {
  strings:
    $key_03ec = { 50 83 [2] 74 8d [2] 5f a1 [2] 71 83 [2] 65 98 [2] 6a 82 [2] 74 9f [2] 76 9e [2] 6d 98 [2] 71 9f [2] 6d b0 }

  condition:
    any of them
}