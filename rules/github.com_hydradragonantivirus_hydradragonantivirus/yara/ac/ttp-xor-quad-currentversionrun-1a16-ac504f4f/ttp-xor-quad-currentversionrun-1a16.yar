rule TTP_XOR_QUAD_CurrentVersionRun_1a16 {
  strings:
    $key_1a16 = { 49 79 [2] 6d 77 [2] 46 5b [2] 68 79 [2] 7c 62 [2] 73 78 [2] 6d 65 [2] 6f 64 [2] 74 62 [2] 68 65 [2] 74 4a }

  condition:
    any of them
}