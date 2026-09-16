rule TTP_XOR_QUAD_CurrentVersionRun_2f42 {
  strings:
    $key_2f42 = { 7c 2d [2] 58 23 [2] 73 0f [2] 5d 2d [2] 49 36 [2] 46 2c [2] 58 31 [2] 5a 30 [2] 41 36 [2] 5d 31 [2] 41 1e }

  condition:
    any of them
}