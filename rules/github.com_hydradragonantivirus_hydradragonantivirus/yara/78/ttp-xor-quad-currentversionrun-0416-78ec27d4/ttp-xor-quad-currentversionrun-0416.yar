rule TTP_XOR_QUAD_CurrentVersionRun_0416 {
  strings:
    $key_0416 = { 57 79 [2] 73 77 [2] 58 5b [2] 76 79 [2] 62 62 [2] 6d 78 [2] 73 65 [2] 71 64 [2] 6a 62 [2] 76 65 [2] 6a 4a }

  condition:
    any of them
}