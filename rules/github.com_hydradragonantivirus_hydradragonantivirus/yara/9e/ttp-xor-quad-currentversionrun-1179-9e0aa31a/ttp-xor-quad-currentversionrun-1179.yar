rule TTP_XOR_QUAD_CurrentVersionRun_1179 {
  strings:
    $key_1179 = { 42 16 [2] 66 18 [2] 4d 34 [2] 63 16 [2] 77 0d [2] 78 17 [2] 66 0a [2] 64 0b [2] 7f 0d [2] 63 0a [2] 7f 25 }

  condition:
    any of them
}