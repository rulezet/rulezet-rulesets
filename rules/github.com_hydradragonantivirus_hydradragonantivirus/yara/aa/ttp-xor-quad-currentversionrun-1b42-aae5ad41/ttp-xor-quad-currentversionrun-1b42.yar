rule TTP_XOR_QUAD_CurrentVersionRun_1b42 {
  strings:
    $key_1b42 = { 48 2d [2] 6c 23 [2] 47 0f [2] 69 2d [2] 7d 36 [2] 72 2c [2] 6c 31 [2] 6e 30 [2] 75 36 [2] 69 31 [2] 75 1e }

  condition:
    any of them
}