rule TTP_XOR_QUAD_CurrentVersionRun_0436 {
  strings:
    $key_0436 = { 57 59 [2] 73 57 [2] 58 7b [2] 76 59 [2] 62 42 [2] 6d 58 [2] 73 45 [2] 71 44 [2] 6a 42 [2] 76 45 [2] 6a 6a }

  condition:
    any of them
}