rule TTP_XOR_QUAD_CurrentVersionRun_7416 {
  strings:
    $key_7416 = { 27 79 [2] 03 77 [2] 28 5b [2] 06 79 [2] 12 62 [2] 1d 78 [2] 03 65 [2] 01 64 [2] 1a 62 [2] 06 65 [2] 1a 4a }

  condition:
    any of them
}