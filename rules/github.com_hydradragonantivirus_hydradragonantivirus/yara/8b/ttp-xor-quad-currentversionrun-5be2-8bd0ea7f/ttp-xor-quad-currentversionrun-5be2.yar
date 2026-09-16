rule TTP_XOR_QUAD_CurrentVersionRun_5be2 {
  strings:
    $key_5be2 = { 08 8d [2] 2c 83 [2] 07 af [2] 29 8d [2] 3d 96 [2] 32 8c [2] 2c 91 [2] 2e 90 [2] 35 96 [2] 29 91 [2] 35 be }

  condition:
    any of them
}