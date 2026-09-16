rule TTP_XOR_QUAD_CurrentVersionRun_5bec {
  strings:
    $key_5bec = { 08 83 [2] 2c 8d [2] 07 a1 [2] 29 83 [2] 3d 98 [2] 32 82 [2] 2c 9f [2] 2e 9e [2] 35 98 [2] 29 9f [2] 35 b0 }

  condition:
    any of them
}