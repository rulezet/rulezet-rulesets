rule TTP_XOR_QUAD_CurrentVersionRun_5a46 {
  strings:
    $key_5a46 = { 09 29 [2] 2d 27 [2] 06 0b [2] 28 29 [2] 3c 32 [2] 33 28 [2] 2d 35 [2] 2f 34 [2] 34 32 [2] 28 35 [2] 34 1a }

  condition:
    any of them
}