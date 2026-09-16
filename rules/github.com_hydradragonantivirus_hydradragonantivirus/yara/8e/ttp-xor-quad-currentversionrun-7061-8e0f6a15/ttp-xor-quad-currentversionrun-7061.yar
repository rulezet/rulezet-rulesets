rule TTP_XOR_QUAD_CurrentVersionRun_7061 {
  strings:
    $key_7061 = { 23 0e [2] 07 00 [2] 2c 2c [2] 02 0e [2] 16 15 [2] 19 0f [2] 07 12 [2] 05 13 [2] 1e 15 [2] 02 12 [2] 1e 3d }

  condition:
    any of them
}