rule TTP_XOR_QUAD_CurrentVersionRun_3642 {
  strings:
    $key_3642 = { 65 2d [2] 41 23 [2] 6a 0f [2] 44 2d [2] 50 36 [2] 5f 2c [2] 41 31 [2] 43 30 [2] 58 36 [2] 44 31 [2] 58 1e }

  condition:
    any of them
}