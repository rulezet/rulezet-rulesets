rule TTP_XOR_QUAD_CurrentVersionRun_1d16 {
  strings:
    $key_1d16 = { 4e 79 [2] 6a 77 [2] 41 5b [2] 6f 79 [2] 7b 62 [2] 74 78 [2] 6a 65 [2] 68 64 [2] 73 62 [2] 6f 65 [2] 73 4a }

  condition:
    any of them
}