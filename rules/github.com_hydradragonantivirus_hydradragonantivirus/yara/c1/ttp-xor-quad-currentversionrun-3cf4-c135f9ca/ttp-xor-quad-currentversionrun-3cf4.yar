rule TTP_XOR_QUAD_CurrentVersionRun_3cf4 {
  strings:
    $key_3cf4 = { 6f 9b [2] 4b 95 [2] 60 b9 [2] 4e 9b [2] 5a 80 [2] 55 9a [2] 4b 87 [2] 49 86 [2] 52 80 [2] 4e 87 [2] 52 a8 }

  condition:
    any of them
}