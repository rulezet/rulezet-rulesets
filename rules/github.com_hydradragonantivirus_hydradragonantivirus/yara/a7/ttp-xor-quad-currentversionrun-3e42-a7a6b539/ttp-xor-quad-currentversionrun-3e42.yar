rule TTP_XOR_QUAD_CurrentVersionRun_3e42 {
  strings:
    $key_3e42 = { 6d 2d [2] 49 23 [2] 62 0f [2] 4c 2d [2] 58 36 [2] 57 2c [2] 49 31 [2] 4b 30 [2] 50 36 [2] 4c 31 [2] 50 1e }

  condition:
    any of them
}