rule TTP_XOR_QUAD_CurrentVersionRun_1156 {
  strings:
    $key_1156 = { 42 39 [2] 66 37 [2] 4d 1b [2] 63 39 [2] 77 22 [2] 78 38 [2] 66 25 [2] 64 24 [2] 7f 22 [2] 63 25 [2] 7f 0a }

  condition:
    any of them
}