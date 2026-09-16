rule TTP_XOR_QUAD_CurrentVersionRun_2342 {
  strings:
    $key_2342 = { 70 2d [2] 54 23 [2] 7f 0f [2] 51 2d [2] 45 36 [2] 4a 2c [2] 54 31 [2] 56 30 [2] 4d 36 [2] 51 31 [2] 4d 1e }

  condition:
    any of them
}