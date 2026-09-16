rule TTP_XOR_QUAD_CurrentVersionRun_5436 {
  strings:
    $key_5436 = { 07 59 [2] 23 57 [2] 08 7b [2] 26 59 [2] 32 42 [2] 3d 58 [2] 23 45 [2] 21 44 [2] 3a 42 [2] 26 45 [2] 3a 6a }

  condition:
    any of them
}