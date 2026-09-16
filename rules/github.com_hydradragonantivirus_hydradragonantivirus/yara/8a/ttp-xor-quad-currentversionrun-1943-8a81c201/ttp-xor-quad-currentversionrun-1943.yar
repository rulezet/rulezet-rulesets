rule TTP_XOR_QUAD_CurrentVersionRun_1943 {
  strings:
    $key_1943 = { 4a 2c [2] 6e 22 [2] 45 0e [2] 6b 2c [2] 7f 37 [2] 70 2d [2] 6e 30 [2] 6c 31 [2] 77 37 [2] 6b 30 [2] 77 1f }

  condition:
    any of them
}