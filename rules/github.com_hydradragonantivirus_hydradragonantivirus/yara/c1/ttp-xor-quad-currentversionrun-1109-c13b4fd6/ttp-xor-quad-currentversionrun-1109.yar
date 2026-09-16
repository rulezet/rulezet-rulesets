rule TTP_XOR_QUAD_CurrentVersionRun_1109 {
  strings:
    $key_1109 = { 42 66 [2] 66 68 [2] 4d 44 [2] 63 66 [2] 77 7d [2] 78 67 [2] 66 7a [2] 64 7b [2] 7f 7d [2] 63 7a [2] 7f 55 }

  condition:
    any of them
}