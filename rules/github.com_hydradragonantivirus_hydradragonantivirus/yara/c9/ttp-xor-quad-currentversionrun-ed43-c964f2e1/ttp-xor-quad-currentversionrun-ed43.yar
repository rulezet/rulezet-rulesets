rule TTP_XOR_QUAD_CurrentVersionRun_ed43 {
  strings:
    $key_ed43 = { be 2c [2] 9a 22 [2] b1 0e [2] 9f 2c [2] 8b 37 [2] 84 2d [2] 9a 30 [2] 98 31 [2] 83 37 [2] 9f 30 [2] 83 1f }

  condition:
    any of them
}