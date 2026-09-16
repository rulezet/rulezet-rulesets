rule TTP_XOR_QUAD_CurrentVersionRun_fbf4 {
  strings:
    $key_fbf4 = { a8 9b [2] 8c 95 [2] a7 b9 [2] 89 9b [2] 9d 80 [2] 92 9a [2] 8c 87 [2] 8e 86 [2] 95 80 [2] 89 87 [2] 95 a8 }

  condition:
    any of them
}