rule TTP_XOR_QUAD_CurrentVersionRun_7b16 {
  strings:
    $key_7b16 = { 28 79 [2] 0c 77 [2] 27 5b [2] 09 79 [2] 1d 62 [2] 12 78 [2] 0c 65 [2] 0e 64 [2] 15 62 [2] 09 65 [2] 15 4a }

  condition:
    any of them
}