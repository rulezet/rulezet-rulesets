rule TTP_XOR_QUAD_CurrentVersionRun_42ef {
  strings:
    $key_42ef = { 11 80 [2] 35 8e [2] 1e a2 [2] 30 80 [2] 24 9b [2] 2b 81 [2] 35 9c [2] 37 9d [2] 2c 9b [2] 30 9c [2] 2c b3 }

  condition:
    any of them
}