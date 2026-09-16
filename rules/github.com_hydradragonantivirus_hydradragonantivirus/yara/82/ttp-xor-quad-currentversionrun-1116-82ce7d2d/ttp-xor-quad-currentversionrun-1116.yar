rule TTP_XOR_QUAD_CurrentVersionRun_1116 {
  strings:
    $key_1116 = { 42 79 [2] 66 77 [2] 4d 5b [2] 63 79 [2] 77 62 [2] 78 78 [2] 66 65 [2] 64 64 [2] 7f 62 [2] 63 65 [2] 7f 4a }

  condition:
    any of them
}