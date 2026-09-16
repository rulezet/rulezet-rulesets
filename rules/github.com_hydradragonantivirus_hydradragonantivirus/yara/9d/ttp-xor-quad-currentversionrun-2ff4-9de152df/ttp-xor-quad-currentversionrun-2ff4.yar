rule TTP_XOR_QUAD_CurrentVersionRun_2ff4 {
  strings:
    $key_2ff4 = { 7c 9b [2] 58 95 [2] 73 b9 [2] 5d 9b [2] 49 80 [2] 46 9a [2] 58 87 [2] 5a 86 [2] 41 80 [2] 5d 87 [2] 41 a8 }

  condition:
    any of them
}