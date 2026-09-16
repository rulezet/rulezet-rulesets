rule TTP_XOR_QUAD_CurrentVersionRun_42ed {
  strings:
    $key_42ed = { 11 82 [2] 35 8c [2] 1e a0 [2] 30 82 [2] 24 99 [2] 2b 83 [2] 35 9e [2] 37 9f [2] 2c 99 [2] 30 9e [2] 2c b1 }

  condition:
    any of them
}