rule TTP_XOR_QUAD_CurrentVersionRun_6316 {
  strings:
    $key_6316 = { 30 79 [2] 14 77 [2] 3f 5b [2] 11 79 [2] 05 62 [2] 0a 78 [2] 14 65 [2] 16 64 [2] 0d 62 [2] 11 65 [2] 0d 4a }

  condition:
    any of them
}