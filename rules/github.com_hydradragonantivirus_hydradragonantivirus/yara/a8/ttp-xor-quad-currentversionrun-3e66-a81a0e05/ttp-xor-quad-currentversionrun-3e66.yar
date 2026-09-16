rule TTP_XOR_QUAD_CurrentVersionRun_3e66 {
  strings:
    $key_3e66 = { 6d 09 [2] 49 07 [2] 62 2b [2] 4c 09 [2] 58 12 [2] 57 08 [2] 49 15 [2] 4b 14 [2] 50 12 [2] 4c 15 [2] 50 3a }

  condition:
    any of them
}