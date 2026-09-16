rule TTP_XOR_QUAD_CurrentVersionRun_3442 {
  strings:
    $key_3442 = { 67 2d [2] 43 23 [2] 68 0f [2] 46 2d [2] 52 36 [2] 5d 2c [2] 43 31 [2] 41 30 [2] 5a 36 [2] 46 31 [2] 5a 1e }

  condition:
    any of them
}