rule TTP_XOR_QUAD_CurrentVersionRun_5b1d {
  strings:
    $key_5b1d = { 08 72 [2] 2c 7c [2] 07 50 [2] 29 72 [2] 3d 69 [2] 32 73 [2] 2c 6e [2] 2e 6f [2] 35 69 [2] 29 6e [2] 35 41 }

  condition:
    any of them
}