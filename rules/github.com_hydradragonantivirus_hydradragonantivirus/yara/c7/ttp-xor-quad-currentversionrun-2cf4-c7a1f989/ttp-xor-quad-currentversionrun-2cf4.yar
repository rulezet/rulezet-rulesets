rule TTP_XOR_QUAD_CurrentVersionRun_2cf4 {
  strings:
    $key_2cf4 = { 7f 9b [2] 5b 95 [2] 70 b9 [2] 5e 9b [2] 4a 80 [2] 45 9a [2] 5b 87 [2] 59 86 [2] 42 80 [2] 5e 87 [2] 42 a8 }

  condition:
    any of them
}