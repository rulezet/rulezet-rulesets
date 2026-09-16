rule TTP_XOR_QUAD_CurrentVersionRun_1516 {
  strings:
    $key_1516 = { 46 79 [2] 62 77 [2] 49 5b [2] 67 79 [2] 73 62 [2] 7c 78 [2] 62 65 [2] 60 64 [2] 7b 62 [2] 67 65 [2] 7b 4a }

  condition:
    any of them
}