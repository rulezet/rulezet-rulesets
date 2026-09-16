rule TTP_XOR_QUAD_CurrentVersionRun_0943 {
  strings:
    $key_0943 = { 5a 2c [2] 7e 22 [2] 55 0e [2] 7b 2c [2] 6f 37 [2] 60 2d [2] 7e 30 [2] 7c 31 [2] 67 37 [2] 7b 30 [2] 67 1f }

  condition:
    any of them
}