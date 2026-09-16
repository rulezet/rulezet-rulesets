rule TTP_XOR_QUAD_CurrentVersionRun_5bf3 {
  strings:
    $key_5bf3 = { 08 9c [2] 2c 92 [2] 07 be [2] 29 9c [2] 3d 87 [2] 32 9d [2] 2c 80 [2] 2e 81 [2] 35 87 [2] 29 80 [2] 35 af }

  condition:
    any of them
}