rule TTP_XOR_QUAD_CurrentVersionRun_3ef4 {
  strings:
    $key_3ef4 = { 6d 9b [2] 49 95 [2] 62 b9 [2] 4c 9b [2] 58 80 [2] 57 9a [2] 49 87 [2] 4b 86 [2] 50 80 [2] 4c 87 [2] 50 a8 }

  condition:
    any of them
}