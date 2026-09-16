rule TTP_XOR_QUAD_CurrentVersionRun_1136 {
  strings:
    $key_1136 = { 42 59 [2] 66 57 [2] 4d 7b [2] 63 59 [2] 77 42 [2] 78 58 [2] 66 45 [2] 64 44 [2] 7f 42 [2] 63 45 [2] 7f 6a }

  condition:
    any of them
}