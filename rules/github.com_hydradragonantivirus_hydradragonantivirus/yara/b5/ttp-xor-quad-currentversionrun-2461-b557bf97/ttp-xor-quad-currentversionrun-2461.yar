rule TTP_XOR_QUAD_CurrentVersionRun_2461 {
  strings:
    $key_2461 = { 77 0e [2] 53 00 [2] 78 2c [2] 56 0e [2] 42 15 [2] 4d 0f [2] 53 12 [2] 51 13 [2] 4a 15 [2] 56 12 [2] 4a 3d }

  condition:
    any of them
}