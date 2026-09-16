rule TTP_XOR_QUAD_CurrentVersionRun_5b51 {
  strings:
    $key_5b51 = { 08 3e [2] 2c 30 [2] 07 1c [2] 29 3e [2] 3d 25 [2] 32 3f [2] 2c 22 [2] 2e 23 [2] 35 25 [2] 29 22 [2] 35 0d }

  condition:
    any of them
}