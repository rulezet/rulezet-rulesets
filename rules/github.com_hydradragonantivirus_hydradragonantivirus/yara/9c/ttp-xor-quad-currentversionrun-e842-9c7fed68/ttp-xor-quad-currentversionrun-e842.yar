rule TTP_XOR_QUAD_CurrentVersionRun_e842 {
  strings:
    $key_e842 = { bb 2d [2] 9f 23 [2] b4 0f [2] 9a 2d [2] 8e 36 [2] 81 2c [2] 9f 31 [2] 9d 30 [2] 86 36 [2] 9a 31 [2] 86 1e }

  condition:
    any of them
}