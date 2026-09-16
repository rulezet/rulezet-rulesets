rule TTP_XOR_QUAD_CurrentVersionRun_1f36 {
  strings:
    $key_1f36 = { 4c 59 [2] 68 57 [2] 43 7b [2] 6d 59 [2] 79 42 [2] 76 58 [2] 68 45 [2] 6a 44 [2] 71 42 [2] 6d 45 [2] 71 6a }

  condition:
    any of them
}