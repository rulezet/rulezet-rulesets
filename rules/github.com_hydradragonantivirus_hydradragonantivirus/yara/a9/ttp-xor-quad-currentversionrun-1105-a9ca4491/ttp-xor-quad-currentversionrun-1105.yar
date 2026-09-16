rule TTP_XOR_QUAD_CurrentVersionRun_1105 {
  strings:
    $key_1105 = { 42 6a [2] 66 64 [2] 4d 48 [2] 63 6a [2] 77 71 [2] 78 6b [2] 66 76 [2] 64 77 [2] 7f 71 [2] 63 76 [2] 7f 59 }

  condition:
    any of them
}