rule TTP_XOR_QUAD_CurrentVersionRun_42ec {
  strings:
    $key_42ec = { 11 83 [2] 35 8d [2] 1e a1 [2] 30 83 [2] 24 98 [2] 2b 82 [2] 35 9f [2] 37 9e [2] 2c 98 [2] 30 9f [2] 2c b0 }

  condition:
    any of them
}