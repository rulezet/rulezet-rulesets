rule TTP_XOR_QUAD_CurrentVersionRun_ebf4 {
  strings:
    $key_ebf4 = { b8 9b [2] 9c 95 [2] b7 b9 [2] 99 9b [2] 8d 80 [2] 82 9a [2] 9c 87 [2] 9e 86 [2] 85 80 [2] 99 87 [2] 85 a8 }

  condition:
    any of them
}