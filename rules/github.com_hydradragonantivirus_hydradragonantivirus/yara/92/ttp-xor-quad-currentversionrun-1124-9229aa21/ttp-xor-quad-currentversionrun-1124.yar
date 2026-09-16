rule TTP_XOR_QUAD_CurrentVersionRun_1124 {
  strings:
    $key_1124 = { 42 4b [2] 66 45 [2] 4d 69 [2] 63 4b [2] 77 50 [2] 78 4a [2] 66 57 [2] 64 56 [2] 7f 50 [2] 63 57 [2] 7f 78 }

  condition:
    any of them
}