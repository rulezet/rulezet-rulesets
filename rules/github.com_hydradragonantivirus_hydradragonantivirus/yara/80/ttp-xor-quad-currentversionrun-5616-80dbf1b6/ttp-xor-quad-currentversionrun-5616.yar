rule TTP_XOR_QUAD_CurrentVersionRun_5616 {
  strings:
    $key_5616 = { 05 79 [2] 21 77 [2] 0a 5b [2] 24 79 [2] 30 62 [2] 3f 78 [2] 21 65 [2] 23 64 [2] 38 62 [2] 24 65 [2] 38 4a }

  condition:
    any of them
}