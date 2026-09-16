rule TTP_XOR_QUAD_CurrentVersionRun_0ef4 {
  strings:
    $key_0ef4 = { 5d 9b [2] 79 95 [2] 52 b9 [2] 7c 9b [2] 68 80 [2] 67 9a [2] 79 87 [2] 7b 86 [2] 60 80 [2] 7c 87 [2] 60 a8 }

  condition:
    any of them
}