rule TTP_XOR_QUAD_CurrentVersionRun_1114 {
  strings:
    $key_1114 = { 42 7b [2] 66 75 [2] 4d 59 [2] 63 7b [2] 77 60 [2] 78 7a [2] 66 67 [2] 64 66 [2] 7f 60 [2] 63 67 [2] 7f 48 }

  condition:
    any of them
}