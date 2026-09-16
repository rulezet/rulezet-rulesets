rule TTP_XOR_QUAD_CurrentVersionRun_6c16 {
  strings:
    $key_6c16 = { 3f 79 [2] 1b 77 [2] 30 5b [2] 1e 79 [2] 0a 62 [2] 05 78 [2] 1b 65 [2] 19 64 [2] 02 62 [2] 1e 65 [2] 02 4a }

  condition:
    any of them
}