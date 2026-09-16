rule TTP_XOR_QUAD_CurrentVersionRun_6616 {
  strings:
    $key_6616 = { 35 79 [2] 11 77 [2] 3a 5b [2] 14 79 [2] 00 62 [2] 0f 78 [2] 11 65 [2] 13 64 [2] 08 62 [2] 14 65 [2] 08 4a }

  condition:
    any of them
}