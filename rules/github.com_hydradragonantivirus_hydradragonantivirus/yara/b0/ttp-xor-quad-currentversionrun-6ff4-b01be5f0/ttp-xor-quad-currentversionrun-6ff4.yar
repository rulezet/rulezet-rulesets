rule TTP_XOR_QUAD_CurrentVersionRun_6ff4 {
  strings:
    $key_6ff4 = { 3c 9b [2] 18 95 [2] 33 b9 [2] 1d 9b [2] 09 80 [2] 06 9a [2] 18 87 [2] 1a 86 [2] 01 80 [2] 1d 87 [2] 01 a8 }

  condition:
    any of them
}