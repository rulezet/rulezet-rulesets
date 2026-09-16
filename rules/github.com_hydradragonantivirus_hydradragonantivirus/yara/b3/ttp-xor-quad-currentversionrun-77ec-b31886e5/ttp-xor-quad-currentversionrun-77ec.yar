rule TTP_XOR_QUAD_CurrentVersionRun_77ec {
  strings:
    $key_77ec = { 24 83 [2] 00 8d [2] 2b a1 [2] 05 83 [2] 11 98 [2] 1e 82 [2] 00 9f [2] 02 9e [2] 19 98 [2] 05 9f [2] 19 b0 }

  condition:
    any of them
}