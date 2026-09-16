rule TTP_XOR_QUAD_CurrentVersionRun_7316 {
  strings:
    $key_7316 = { 20 79 [2] 04 77 [2] 2f 5b [2] 01 79 [2] 15 62 [2] 1a 78 [2] 04 65 [2] 06 64 [2] 1d 62 [2] 01 65 [2] 1d 4a }

  condition:
    any of them
}