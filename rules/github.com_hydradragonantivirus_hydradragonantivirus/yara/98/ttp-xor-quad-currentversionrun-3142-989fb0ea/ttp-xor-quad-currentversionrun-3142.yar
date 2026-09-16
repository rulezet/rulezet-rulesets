rule TTP_XOR_QUAD_CurrentVersionRun_3142 {
  strings:
    $key_3142 = { 62 2d [2] 46 23 [2] 6d 0f [2] 43 2d [2] 57 36 [2] 58 2c [2] 46 31 [2] 44 30 [2] 5f 36 [2] 43 31 [2] 5f 1e }

  condition:
    any of them
}