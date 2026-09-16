rule TTP_XOR_QUAD_CurrentVersionRun_46ec {
  strings:
    $key_46ec = { 15 83 [2] 31 8d [2] 1a a1 [2] 34 83 [2] 20 98 [2] 2f 82 [2] 31 9f [2] 33 9e [2] 28 98 [2] 34 9f [2] 28 b0 }

  condition:
    any of them
}