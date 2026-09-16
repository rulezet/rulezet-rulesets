rule TTP_XOR_QUAD_CurrentVersionRun_5b2d {
  strings:
    $key_5b2d = { 08 42 [2] 2c 4c [2] 07 60 [2] 29 42 [2] 3d 59 [2] 32 43 [2] 2c 5e [2] 2e 5f [2] 35 59 [2] 29 5e [2] 35 71 }

  condition:
    any of them
}