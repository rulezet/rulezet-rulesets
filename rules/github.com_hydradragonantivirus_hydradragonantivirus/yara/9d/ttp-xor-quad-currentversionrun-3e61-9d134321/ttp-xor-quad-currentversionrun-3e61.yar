rule TTP_XOR_QUAD_CurrentVersionRun_3e61 {
  strings:
    $key_3e61 = { 6d 0e [2] 49 00 [2] 62 2c [2] 4c 0e [2] 58 15 [2] 57 0f [2] 49 12 [2] 4b 13 [2] 50 15 [2] 4c 12 [2] 50 3d }

  condition:
    any of them
}