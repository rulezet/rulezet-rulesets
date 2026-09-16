rule TTP_XOR_QUAD_CurrentVersionRun_1137 {
  strings:
    $key_1137 = { 42 58 [2] 66 56 [2] 4d 7a [2] 63 58 [2] 77 43 [2] 78 59 [2] 66 44 [2] 64 45 [2] 7f 43 [2] 63 44 [2] 7f 6b }

  condition:
    any of them
}