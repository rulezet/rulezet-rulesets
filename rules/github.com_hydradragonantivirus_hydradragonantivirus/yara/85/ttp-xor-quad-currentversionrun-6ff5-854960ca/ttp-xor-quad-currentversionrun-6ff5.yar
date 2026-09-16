rule TTP_XOR_QUAD_CurrentVersionRun_6ff5 {
  strings:
    $key_6ff5 = { 3c 9a [2] 18 94 [2] 33 b8 [2] 1d 9a [2] 09 81 [2] 06 9b [2] 18 86 [2] 1a 87 [2] 01 81 [2] 1d 86 [2] 01 a9 }

  condition:
    any of them
}