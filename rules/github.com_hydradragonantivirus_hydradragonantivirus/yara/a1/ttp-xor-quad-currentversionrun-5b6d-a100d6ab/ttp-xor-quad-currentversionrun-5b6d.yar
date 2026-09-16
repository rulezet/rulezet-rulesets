rule TTP_XOR_QUAD_CurrentVersionRun_5b6d {
  strings:
    $key_5b6d = { 08 02 [2] 2c 0c [2] 07 20 [2] 29 02 [2] 3d 19 [2] 32 03 [2] 2c 1e [2] 2e 1f [2] 35 19 [2] 29 1e [2] 35 31 }

  condition:
    any of them
}