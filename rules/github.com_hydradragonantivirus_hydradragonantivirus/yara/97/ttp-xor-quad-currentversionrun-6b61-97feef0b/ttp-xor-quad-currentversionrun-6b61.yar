rule TTP_XOR_QUAD_CurrentVersionRun_6b61 {
  strings:
    $key_6b61 = { 38 0e [2] 1c 00 [2] 37 2c [2] 19 0e [2] 0d 15 [2] 02 0f [2] 1c 12 [2] 1e 13 [2] 05 15 [2] 19 12 [2] 05 3d }

  condition:
    any of them
}