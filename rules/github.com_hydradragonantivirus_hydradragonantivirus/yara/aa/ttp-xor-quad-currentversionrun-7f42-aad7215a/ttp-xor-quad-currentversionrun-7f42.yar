rule TTP_XOR_QUAD_CurrentVersionRun_7f42 {
  strings:
    $key_7f42 = { 2c 2d [2] 08 23 [2] 23 0f [2] 0d 2d [2] 19 36 [2] 16 2c [2] 08 31 [2] 0a 30 [2] 11 36 [2] 0d 31 [2] 11 1e }

  condition:
    any of them
}