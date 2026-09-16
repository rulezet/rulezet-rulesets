rule TTP_XOR_QUAD_CurrentVersionRun_6e2c {
  strings:
    $key_6e2c = { 3d 43 [2] 19 4d [2] 32 61 [2] 1c 43 [2] 08 58 [2] 07 42 [2] 19 5f [2] 1b 5e [2] 00 58 [2] 1c 5f [2] 00 70 }

  condition:
    any of them
}