rule TTP_XOR_QUAD_CurrentVersionRun_7a42 {
  strings:
    $key_7a42 = { 29 2d [2] 0d 23 [2] 26 0f [2] 08 2d [2] 1c 36 [2] 13 2c [2] 0d 31 [2] 0f 30 [2] 14 36 [2] 08 31 [2] 14 1e }

  condition:
    any of them
}