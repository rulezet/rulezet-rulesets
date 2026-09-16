rule TTP_XOR_QUAD_CurrentVersionRun_1a42 {
  strings:
    $key_1a42 = { 49 2d [2] 6d 23 [2] 46 0f [2] 68 2d [2] 7c 36 [2] 73 2c [2] 6d 31 [2] 6f 30 [2] 74 36 [2] 68 31 [2] 74 1e }

  condition:
    any of them
}