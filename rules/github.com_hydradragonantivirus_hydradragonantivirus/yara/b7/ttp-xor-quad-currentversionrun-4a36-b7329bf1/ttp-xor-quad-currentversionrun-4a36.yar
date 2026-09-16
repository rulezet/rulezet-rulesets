rule TTP_XOR_QUAD_CurrentVersionRun_4a36 {
  strings:
    $key_4a36 = { 19 59 [2] 3d 57 [2] 16 7b [2] 38 59 [2] 2c 42 [2] 23 58 [2] 3d 45 [2] 3f 44 [2] 24 42 [2] 38 45 [2] 24 6a }

  condition:
    any of them
}