rule TTP_XOR_QUAD_CurrentVersionRun_ed42 {
  strings:
    $key_ed42 = { be 2d [2] 9a 23 [2] b1 0f [2] 9f 2d [2] 8b 36 [2] 84 2c [2] 9a 31 [2] 98 30 [2] 83 36 [2] 9f 31 [2] 83 1e }

  condition:
    any of them
}