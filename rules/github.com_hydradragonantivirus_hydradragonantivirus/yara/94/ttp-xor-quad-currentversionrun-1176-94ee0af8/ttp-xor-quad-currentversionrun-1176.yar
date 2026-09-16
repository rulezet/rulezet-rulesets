rule TTP_XOR_QUAD_CurrentVersionRun_1176 {
  strings:
    $key_1176 = { 42 19 [2] 66 17 [2] 4d 3b [2] 63 19 [2] 77 02 [2] 78 18 [2] 66 05 [2] 64 04 [2] 7f 02 [2] 63 05 [2] 7f 2a }

  condition:
    any of them
}