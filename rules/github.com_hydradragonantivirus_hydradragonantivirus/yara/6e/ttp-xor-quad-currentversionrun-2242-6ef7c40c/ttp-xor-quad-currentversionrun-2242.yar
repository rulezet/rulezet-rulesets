rule TTP_XOR_QUAD_CurrentVersionRun_2242 {
  strings:
    $key_2242 = { 71 2d [2] 55 23 [2] 7e 0f [2] 50 2d [2] 44 36 [2] 4b 2c [2] 55 31 [2] 57 30 [2] 4c 36 [2] 50 31 [2] 4c 1e }

  condition:
    any of them
}