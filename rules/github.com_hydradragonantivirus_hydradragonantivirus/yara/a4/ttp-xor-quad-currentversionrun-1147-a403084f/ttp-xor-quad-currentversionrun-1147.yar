rule TTP_XOR_QUAD_CurrentVersionRun_1147 {
  strings:
    $key_1147 = { 42 28 [2] 66 26 [2] 4d 0a [2] 63 28 [2] 77 33 [2] 78 29 [2] 66 34 [2] 64 35 [2] 7f 33 [2] 63 34 [2] 7f 1b }

  condition:
    any of them
}