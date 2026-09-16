rule TTP_XOR_QUAD_CurrentVersionRun_2b61 {
  strings:
    $key_2b61 = { 78 0e [2] 5c 00 [2] 77 2c [2] 59 0e [2] 4d 15 [2] 42 0f [2] 5c 12 [2] 5e 13 [2] 45 15 [2] 59 12 [2] 45 3d }

  condition:
    any of them
}