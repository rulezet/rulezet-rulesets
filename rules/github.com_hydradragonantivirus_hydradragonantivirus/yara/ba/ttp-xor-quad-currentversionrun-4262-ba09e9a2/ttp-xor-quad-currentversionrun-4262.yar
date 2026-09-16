rule TTP_XOR_QUAD_CurrentVersionRun_4262 {
  strings:
    $key_4262 = { 11 0d [2] 35 03 [2] 1e 2f [2] 30 0d [2] 24 16 [2] 2b 0c [2] 35 11 [2] 37 10 [2] 2c 16 [2] 30 11 [2] 2c 3e }

  condition:
    any of them
}