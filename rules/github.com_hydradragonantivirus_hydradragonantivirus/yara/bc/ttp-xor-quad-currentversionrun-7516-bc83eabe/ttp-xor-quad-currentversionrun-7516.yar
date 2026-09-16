rule TTP_XOR_QUAD_CurrentVersionRun_7516 {
  strings:
    $key_7516 = { 26 79 [2] 02 77 [2] 29 5b [2] 07 79 [2] 13 62 [2] 1c 78 [2] 02 65 [2] 00 64 [2] 1b 62 [2] 07 65 [2] 1b 4a }

  condition:
    any of them
}