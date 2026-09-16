rule TTP_XOR_QUAD_CurrentVersionRun_3b36 {
  strings:
    $key_3b36 = { 68 59 [2] 4c 57 [2] 67 7b [2] 49 59 [2] 5d 42 [2] 52 58 [2] 4c 45 [2] 4e 44 [2] 55 42 [2] 49 45 [2] 55 6a }

  condition:
    any of them
}