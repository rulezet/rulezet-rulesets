rule TTP_XOR_QUAD_CurrentVersionRun_4512 {
  strings:
    $key_4512 = { 16 7d [2] 32 73 [2] 19 5f [2] 37 7d [2] 23 66 [2] 2c 7c [2] 32 61 [2] 30 60 [2] 2b 66 [2] 37 61 [2] 2b 4e }

  condition:
    any of them
}