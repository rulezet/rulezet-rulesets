rule TTP_XOR_QUAD_CurrentVersionRun_2ff5 {
  strings:
    $key_2ff5 = { 7c 9a [2] 58 94 [2] 73 b8 [2] 5d 9a [2] 49 81 [2] 46 9b [2] 58 86 [2] 5a 87 [2] 41 81 [2] 5d 86 [2] 41 a9 }

  condition:
    any of them
}