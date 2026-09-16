rule TTP_XOR_QUAD_CurrentVersionRun_52ec {
  strings:
    $key_52ec = { 01 83 [2] 25 8d [2] 0e a1 [2] 20 83 [2] 34 98 [2] 3b 82 [2] 25 9f [2] 27 9e [2] 3c 98 [2] 20 9f [2] 3c b0 }

  condition:
    any of them
}