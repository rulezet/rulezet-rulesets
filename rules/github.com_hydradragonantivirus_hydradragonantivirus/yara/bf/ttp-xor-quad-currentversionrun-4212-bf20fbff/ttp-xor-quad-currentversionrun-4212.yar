rule TTP_XOR_QUAD_CurrentVersionRun_4212 {
  strings:
    $key_4212 = { 11 7d [2] 35 73 [2] 1e 5f [2] 30 7d [2] 24 66 [2] 2b 7c [2] 35 61 [2] 37 60 [2] 2c 66 [2] 30 61 [2] 2c 4e }

  condition:
    any of them
}