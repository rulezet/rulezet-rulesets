rule TTP_XOR_QUAD_CurrentVersionRun_6916 {
  strings:
    $key_6916 = { 3a 79 [2] 1e 77 [2] 35 5b [2] 1b 79 [2] 0f 62 [2] 00 78 [2] 1e 65 [2] 1c 64 [2] 07 62 [2] 1b 65 [2] 07 4a }

  condition:
    any of them
}