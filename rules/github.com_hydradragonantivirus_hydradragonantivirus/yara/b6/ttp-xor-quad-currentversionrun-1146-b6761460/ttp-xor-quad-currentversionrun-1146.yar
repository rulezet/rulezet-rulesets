rule TTP_XOR_QUAD_CurrentVersionRun_1146 {
  strings:
    $key_1146 = { 42 29 [2] 66 27 [2] 4d 0b [2] 63 29 [2] 77 32 [2] 78 28 [2] 66 35 [2] 64 34 [2] 7f 32 [2] 63 35 [2] 7f 1a }

  condition:
    any of them
}