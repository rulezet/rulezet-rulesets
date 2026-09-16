rule TTP_XOR_QUAD_CurrentVersionRun_7916 {
  strings:
    $key_7916 = { 2a 79 [2] 0e 77 [2] 25 5b [2] 0b 79 [2] 1f 62 [2] 10 78 [2] 0e 65 [2] 0c 64 [2] 17 62 [2] 0b 65 [2] 17 4a }

  condition:
    any of them
}