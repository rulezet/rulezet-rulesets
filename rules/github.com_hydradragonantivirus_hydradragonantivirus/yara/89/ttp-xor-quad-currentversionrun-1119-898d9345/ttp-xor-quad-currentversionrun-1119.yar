rule TTP_XOR_QUAD_CurrentVersionRun_1119 {
  strings:
    $key_1119 = { 42 76 [2] 66 78 [2] 4d 54 [2] 63 76 [2] 77 6d [2] 78 77 [2] 66 6a [2] 64 6b [2] 7f 6d [2] 63 6a [2] 7f 45 }

  condition:
    any of them
}