rule TTP_XOR_QUAD_CurrentVersionRun_5b4c {
  strings:
    $key_5b4c = { 08 23 [2] 2c 2d [2] 07 01 [2] 29 23 [2] 3d 38 [2] 32 22 [2] 2c 3f [2] 2e 3e [2] 35 38 [2] 29 3f [2] 35 10 }

  condition:
    any of them
}