rule TTP_XOR_QUAD_CurrentVersionRun_36ec {
  strings:
    $key_36ec = { 65 83 [2] 41 8d [2] 6a a1 [2] 44 83 [2] 50 98 [2] 5f 82 [2] 41 9f [2] 43 9e [2] 58 98 [2] 44 9f [2] 58 b0 }

  condition:
    any of them
}