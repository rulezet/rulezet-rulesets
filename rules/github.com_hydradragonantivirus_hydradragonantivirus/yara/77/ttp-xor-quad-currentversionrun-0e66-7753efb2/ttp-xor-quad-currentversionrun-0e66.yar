rule TTP_XOR_QUAD_CurrentVersionRun_0e66 {
  strings:
    $key_0e66 = { 5d 09 [2] 79 07 [2] 52 2b [2] 7c 09 [2] 68 12 [2] 67 08 [2] 79 15 [2] 7b 14 [2] 60 12 [2] 7c 15 [2] 60 3a }

  condition:
    any of them
}