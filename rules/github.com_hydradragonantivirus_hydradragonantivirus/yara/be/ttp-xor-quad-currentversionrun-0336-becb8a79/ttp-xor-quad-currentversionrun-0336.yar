rule TTP_XOR_QUAD_CurrentVersionRun_0336 {
  strings:
    $key_0336 = { 50 59 [2] 74 57 [2] 5f 7b [2] 71 59 [2] 65 42 [2] 6a 58 [2] 74 45 [2] 76 44 [2] 6d 42 [2] 71 45 [2] 6d 6a }

  condition:
    any of them
}