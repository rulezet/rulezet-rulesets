rule TTP_XOR_QUAD_CurrentVersionRun_1b16 {
  strings:
    $key_1b16 = { 48 79 [2] 6c 77 [2] 47 5b [2] 69 79 [2] 7d 62 [2] 72 78 [2] 6c 65 [2] 6e 64 [2] 75 62 [2] 69 65 [2] 75 4a }

  condition:
    any of them
}