rule TTP_XOR_QUAD_CurrentVersionRun_5b7c {
  strings:
    $key_5b7c = { 08 13 [2] 2c 1d [2] 07 31 [2] 29 13 [2] 3d 08 [2] 32 12 [2] 2c 0f [2] 2e 0e [2] 35 08 [2] 29 0f [2] 35 20 }

  condition:
    any of them
}