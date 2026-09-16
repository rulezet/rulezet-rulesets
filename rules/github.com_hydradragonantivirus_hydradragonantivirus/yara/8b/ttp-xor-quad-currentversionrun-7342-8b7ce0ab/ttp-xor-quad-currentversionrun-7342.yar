rule TTP_XOR_QUAD_CurrentVersionRun_7342 {
  strings:
    $key_7342 = { 20 2d [2] 04 23 [2] 2f 0f [2] 01 2d [2] 15 36 [2] 1a 2c [2] 04 31 [2] 06 30 [2] 1d 36 [2] 01 31 [2] 1d 1e }

  condition:
    any of them
}