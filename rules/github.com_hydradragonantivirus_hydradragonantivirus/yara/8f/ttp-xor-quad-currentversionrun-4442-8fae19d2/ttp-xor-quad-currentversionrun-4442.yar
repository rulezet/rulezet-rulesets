rule TTP_XOR_QUAD_CurrentVersionRun_4442 {
  strings:
    $key_4442 = { 17 2d [2] 33 23 [2] 18 0f [2] 36 2d [2] 22 36 [2] 2d 2c [2] 33 31 [2] 31 30 [2] 2a 36 [2] 36 31 [2] 2a 1e }

  condition:
    any of them
}