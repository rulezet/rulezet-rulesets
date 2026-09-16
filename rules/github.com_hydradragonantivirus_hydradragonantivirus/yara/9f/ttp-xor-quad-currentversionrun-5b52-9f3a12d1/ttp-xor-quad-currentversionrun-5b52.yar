rule TTP_XOR_QUAD_CurrentVersionRun_5b52 {
  strings:
    $key_5b52 = { 08 3d [2] 2c 33 [2] 07 1f [2] 29 3d [2] 3d 26 [2] 32 3c [2] 2c 21 [2] 2e 20 [2] 35 26 [2] 29 21 [2] 35 0e }

  condition:
    any of them
}