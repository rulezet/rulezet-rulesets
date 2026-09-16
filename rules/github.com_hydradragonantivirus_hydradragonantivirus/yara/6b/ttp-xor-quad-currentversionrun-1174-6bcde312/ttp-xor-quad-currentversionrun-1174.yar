rule TTP_XOR_QUAD_CurrentVersionRun_1174 {
  strings:
    $key_1174 = { 42 1b [2] 66 15 [2] 4d 39 [2] 63 1b [2] 77 00 [2] 78 1a [2] 66 07 [2] 64 06 [2] 7f 00 [2] 63 07 [2] 7f 28 }

  condition:
    any of them
}