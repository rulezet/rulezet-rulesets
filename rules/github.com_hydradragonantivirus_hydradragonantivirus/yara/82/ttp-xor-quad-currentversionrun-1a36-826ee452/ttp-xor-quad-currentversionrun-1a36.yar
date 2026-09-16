rule TTP_XOR_QUAD_CurrentVersionRun_1a36 {
  strings:
    $key_1a36 = { 49 59 [2] 6d 57 [2] 46 7b [2] 68 59 [2] 7c 42 [2] 73 58 [2] 6d 45 [2] 6f 44 [2] 74 42 [2] 68 45 [2] 74 6a }

  condition:
    any of them
}