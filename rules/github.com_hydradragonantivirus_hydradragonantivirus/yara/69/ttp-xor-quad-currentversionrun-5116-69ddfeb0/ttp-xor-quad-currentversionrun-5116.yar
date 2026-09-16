rule TTP_XOR_QUAD_CurrentVersionRun_5116 {
  strings:
    $key_5116 = { 02 79 [2] 26 77 [2] 0d 5b [2] 23 79 [2] 37 62 [2] 38 78 [2] 26 65 [2] 24 64 [2] 3f 62 [2] 23 65 [2] 3f 4a }

  condition:
    any of them
}