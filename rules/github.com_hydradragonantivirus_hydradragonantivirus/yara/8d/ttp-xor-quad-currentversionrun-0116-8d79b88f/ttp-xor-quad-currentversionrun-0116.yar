rule TTP_XOR_QUAD_CurrentVersionRun_0116 {
  strings:
    $key_0116 = { 52 79 [2] 76 77 [2] 5d 5b [2] 73 79 [2] 67 62 [2] 68 78 [2] 76 65 [2] 74 64 [2] 6f 62 [2] 73 65 [2] 6f 4a }

  condition:
    any of them
}