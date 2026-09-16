rule TTP_XOR_QUAD_CurrentVersionRun_7561 {
  strings:
    $key_7561 = { 26 0e [2] 02 00 [2] 29 2c [2] 07 0e [2] 13 15 [2] 1c 0f [2] 02 12 [2] 00 13 [2] 1b 15 [2] 07 12 [2] 1b 3d }

  condition:
    any of them
}