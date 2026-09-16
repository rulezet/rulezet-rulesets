rule TTP_XOR_QUAD_CurrentVersionRun_2061 {
  strings:
    $key_2061 = { 73 0e [2] 57 00 [2] 7c 2c [2] 52 0e [2] 46 15 [2] 49 0f [2] 57 12 [2] 55 13 [2] 4e 15 [2] 52 12 [2] 4e 3d }

  condition:
    any of them
}