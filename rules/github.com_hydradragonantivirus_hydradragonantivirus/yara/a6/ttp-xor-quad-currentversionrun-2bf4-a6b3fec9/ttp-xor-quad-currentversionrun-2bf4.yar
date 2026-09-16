rule TTP_XOR_QUAD_CurrentVersionRun_2bf4 {
  strings:
    $key_2bf4 = { 78 9b [2] 5c 95 [2] 77 b9 [2] 59 9b [2] 4d 80 [2] 42 9a [2] 5c 87 [2] 5e 86 [2] 45 80 [2] 59 87 [2] 45 a8 }

  condition:
    any of them
}