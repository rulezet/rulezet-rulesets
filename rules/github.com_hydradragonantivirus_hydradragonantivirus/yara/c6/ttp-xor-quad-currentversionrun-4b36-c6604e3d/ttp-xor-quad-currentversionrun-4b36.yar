rule TTP_XOR_QUAD_CurrentVersionRun_4b36 {
  strings:
    $key_4b36 = { 18 59 [2] 3c 57 [2] 17 7b [2] 39 59 [2] 2d 42 [2] 22 58 [2] 3c 45 [2] 3e 44 [2] 25 42 [2] 39 45 [2] 25 6a }

  condition:
    any of them
}