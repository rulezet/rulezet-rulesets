rule TTP_XOR_QUAD_CurrentVersionRun_1166 {
  strings:
    $key_1166 = { 42 09 [2] 66 07 [2] 4d 2b [2] 63 09 [2] 77 12 [2] 78 08 [2] 66 15 [2] 64 14 [2] 7f 12 [2] 63 15 [2] 7f 3a }

  condition:
    any of them
}