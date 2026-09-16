rule TTP_XOR_QUAD_CurrentVersionRun_08f4 {
  strings:
    $key_08f4 = { 5b 9b [2] 7f 95 [2] 54 b9 [2] 7a 9b [2] 6e 80 [2] 61 9a [2] 7f 87 [2] 7d 86 [2] 66 80 [2] 7a 87 [2] 66 a8 }

  condition:
    any of them
}