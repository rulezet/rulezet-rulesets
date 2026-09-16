rule TTP_XOR_QUAD_CurrentVersionRun_0316 {
  strings:
    $key_0316 = { 50 79 [2] 74 77 [2] 5f 5b [2] 71 79 [2] 65 62 [2] 6a 78 [2] 74 65 [2] 76 64 [2] 6d 62 [2] 71 65 [2] 6d 4a }

  condition:
    any of them
}