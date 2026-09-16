rule TTP_XOR_QUAD_CurrentVersionRun_1164 {
  strings:
    $key_1164 = { 42 0b [2] 66 05 [2] 4d 29 [2] 63 0b [2] 77 10 [2] 78 0a [2] 66 17 [2] 64 16 [2] 7f 10 [2] 63 17 [2] 7f 38 }

  condition:
    any of them
}