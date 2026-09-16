rule TTP_XOR_QUAD_CurrentVersionRun_5b41 {
  strings:
    $key_5b41 = { 08 2e [2] 2c 20 [2] 07 0c [2] 29 2e [2] 3d 35 [2] 32 2f [2] 2c 32 [2] 2e 33 [2] 35 35 [2] 29 32 [2] 35 1d }

  condition:
    any of them
}