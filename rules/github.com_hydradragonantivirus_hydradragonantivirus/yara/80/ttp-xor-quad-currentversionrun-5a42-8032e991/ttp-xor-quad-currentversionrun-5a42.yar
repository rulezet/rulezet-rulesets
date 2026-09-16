rule TTP_XOR_QUAD_CurrentVersionRun_5a42 {
  strings:
    $key_5a42 = { 09 2d [2] 2d 23 [2] 06 0f [2] 28 2d [2] 3c 36 [2] 33 2c [2] 2d 31 [2] 2f 30 [2] 34 36 [2] 28 31 [2] 34 1e }

  condition:
    any of them
}