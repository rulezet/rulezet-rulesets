rule TTP_XOR_QUAD_CurrentVersionRun_6443 {
  strings:
    $key_6443 = { 37 2c [2] 13 22 [2] 38 0e [2] 16 2c [2] 02 37 [2] 0d 2d [2] 13 30 [2] 11 31 [2] 0a 37 [2] 16 30 [2] 0a 1f }

  condition:
    any of them
}