rule TTP_XOR_QUAD_CurrentVersionRun_5ef3 {
  strings:
    $key_5ef3 = { 0d 9c [2] 29 92 [2] 02 be [2] 2c 9c [2] 38 87 [2] 37 9d [2] 29 80 [2] 2b 81 [2] 30 87 [2] 2c 80 [2] 30 af }

  condition:
    any of them
}