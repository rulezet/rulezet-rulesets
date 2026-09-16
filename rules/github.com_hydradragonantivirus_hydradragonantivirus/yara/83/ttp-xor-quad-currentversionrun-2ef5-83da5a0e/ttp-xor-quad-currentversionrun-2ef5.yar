rule TTP_XOR_QUAD_CurrentVersionRun_2ef5 {
  strings:
    $key_2ef5 = { 7d 9a [2] 59 94 [2] 72 b8 [2] 5c 9a [2] 48 81 [2] 47 9b [2] 59 86 [2] 5b 87 [2] 40 81 [2] 5c 86 [2] 40 a9 }

  condition:
    any of them
}