rule TTP_XOR_QUAD_CurrentVersionRun_4e42 {
  strings:
    $key_4e42 = { 1d 2d [2] 39 23 [2] 12 0f [2] 3c 2d [2] 28 36 [2] 27 2c [2] 39 31 [2] 3b 30 [2] 20 36 [2] 3c 31 [2] 20 1e }

  condition:
    any of them
}