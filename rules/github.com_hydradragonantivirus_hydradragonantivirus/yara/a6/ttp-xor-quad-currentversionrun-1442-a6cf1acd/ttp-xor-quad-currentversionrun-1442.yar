rule TTP_XOR_QUAD_CurrentVersionRun_1442 {
  strings:
    $key_1442 = { 47 2d [2] 63 23 [2] 48 0f [2] 66 2d [2] 72 36 [2] 7d 2c [2] 63 31 [2] 61 30 [2] 7a 36 [2] 66 31 [2] 7a 1e }

  condition:
    any of them
}