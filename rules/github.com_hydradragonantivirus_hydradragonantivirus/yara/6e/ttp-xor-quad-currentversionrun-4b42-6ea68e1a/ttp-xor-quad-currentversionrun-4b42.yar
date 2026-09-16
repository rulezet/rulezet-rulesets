rule TTP_XOR_QUAD_CurrentVersionRun_4b42 {
  strings:
    $key_4b42 = { 18 2d [2] 3c 23 [2] 17 0f [2] 39 2d [2] 2d 36 [2] 22 2c [2] 3c 31 [2] 3e 30 [2] 25 36 [2] 39 31 [2] 25 1e }

  condition:
    any of them
}