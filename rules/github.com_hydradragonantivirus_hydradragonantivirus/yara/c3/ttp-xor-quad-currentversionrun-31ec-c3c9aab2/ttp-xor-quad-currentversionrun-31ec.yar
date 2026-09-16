rule TTP_XOR_QUAD_CurrentVersionRun_31ec {
  strings:
    $key_31ec = { 62 83 [2] 46 8d [2] 6d a1 [2] 43 83 [2] 57 98 [2] 58 82 [2] 46 9f [2] 44 9e [2] 5f 98 [2] 43 9f [2] 5f b0 }

  condition:
    any of them
}