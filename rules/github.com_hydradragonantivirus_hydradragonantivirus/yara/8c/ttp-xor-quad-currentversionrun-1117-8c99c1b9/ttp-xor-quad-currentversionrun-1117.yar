rule TTP_XOR_QUAD_CurrentVersionRun_1117 {
  strings:
    $key_1117 = { 42 78 [2] 66 76 [2] 4d 5a [2] 63 78 [2] 77 63 [2] 78 79 [2] 66 64 [2] 64 65 [2] 7f 63 [2] 63 64 [2] 7f 4b }

  condition:
    any of them
}