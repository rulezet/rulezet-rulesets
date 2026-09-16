rule TTP_XOR_QUAD_CurrentVersionRun_6c61 {
  strings:
    $key_6c61 = { 3f 0e [2] 1b 00 [2] 30 2c [2] 1e 0e [2] 0a 15 [2] 05 0f [2] 1b 12 [2] 19 13 [2] 02 15 [2] 1e 12 [2] 02 3d }

  condition:
    any of them
}