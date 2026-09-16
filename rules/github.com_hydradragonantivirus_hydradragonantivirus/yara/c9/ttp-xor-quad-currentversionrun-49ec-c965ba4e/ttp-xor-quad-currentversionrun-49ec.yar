rule TTP_XOR_QUAD_CurrentVersionRun_49ec {
  strings:
    $key_49ec = { 1a 83 [2] 3e 8d [2] 15 a1 [2] 3b 83 [2] 2f 98 [2] 20 82 [2] 3e 9f [2] 3c 9e [2] 27 98 [2] 3b 9f [2] 27 b0 }

  condition:
    any of them
}