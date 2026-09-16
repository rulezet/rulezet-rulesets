rule TTP_XOR_QUAD_CurrentVersionRun_4d61 {
  strings:
    $key_4d61 = { 1e 0e [2] 3a 00 [2] 11 2c [2] 3f 0e [2] 2b 15 [2] 24 0f [2] 3a 12 [2] 38 13 [2] 23 15 [2] 3f 12 [2] 23 3d }

  condition:
    any of them
}