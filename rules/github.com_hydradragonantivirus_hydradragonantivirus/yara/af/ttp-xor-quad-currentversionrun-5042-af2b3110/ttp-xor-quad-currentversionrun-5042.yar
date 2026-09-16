rule TTP_XOR_QUAD_CurrentVersionRun_5042 {
  strings:
    $key_5042 = { 03 2d [2] 27 23 [2] 0c 0f [2] 22 2d [2] 36 36 [2] 39 2c [2] 27 31 [2] 25 30 [2] 3e 36 [2] 22 31 [2] 3e 1e }

  condition:
    any of them
}