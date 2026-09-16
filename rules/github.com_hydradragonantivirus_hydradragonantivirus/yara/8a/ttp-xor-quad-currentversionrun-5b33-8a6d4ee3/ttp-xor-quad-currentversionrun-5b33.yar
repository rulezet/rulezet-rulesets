rule TTP_XOR_QUAD_CurrentVersionRun_5b33 {
  strings:
    $key_5b33 = { 08 5c [2] 2c 52 [2] 07 7e [2] 29 5c [2] 3d 47 [2] 32 5d [2] 2c 40 [2] 2e 41 [2] 35 47 [2] 29 40 [2] 35 6f }

  condition:
    any of them
}