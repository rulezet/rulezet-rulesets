rule TTP_XOR_QUAD_CurrentVersionRun_f161 {
  strings:
    $key_f161 = { a2 0e [2] 86 00 [2] ad 2c [2] 83 0e [2] 97 15 [2] 98 0f [2] 86 12 [2] 84 13 [2] 9f 15 [2] 83 12 [2] 9f 3d }

  condition:
    any of them
}