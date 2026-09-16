rule TTP_XOR_QUAD_CurrentVersionRun_42f3 {
  strings:
    $key_42f3 = { 11 9c [2] 35 92 [2] 1e be [2] 30 9c [2] 24 87 [2] 2b 9d [2] 35 80 [2] 37 81 [2] 2c 87 [2] 30 80 [2] 2c af }

  condition:
    any of them
}