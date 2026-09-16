rule TTP_XOR_QUAD_CurrentVersionRun_5416 {
  strings:
    $key_5416 = { 07 79 [2] 23 77 [2] 08 5b [2] 26 79 [2] 32 62 [2] 3d 78 [2] 23 65 [2] 21 64 [2] 3a 62 [2] 26 65 [2] 3a 4a }

  condition:
    any of them
}