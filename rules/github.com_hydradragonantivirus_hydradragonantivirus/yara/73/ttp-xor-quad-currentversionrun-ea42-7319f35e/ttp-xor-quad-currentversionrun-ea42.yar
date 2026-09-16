rule TTP_XOR_QUAD_CurrentVersionRun_ea42 {
  strings:
    $key_ea42 = { b9 2d [2] 9d 23 [2] b6 0f [2] 98 2d [2] 8c 36 [2] 83 2c [2] 9d 31 [2] 9f 30 [2] 84 36 [2] 98 31 [2] 84 1e }

  condition:
    any of them
}