rule TTP_XOR_QUAD_CurrentVersionRun_5a36 {
  strings:
    $key_5a36 = { 09 59 [2] 2d 57 [2] 06 7b [2] 28 59 [2] 3c 42 [2] 33 58 [2] 2d 45 [2] 2f 44 [2] 34 42 [2] 28 45 [2] 34 6a }

  condition:
    any of them
}