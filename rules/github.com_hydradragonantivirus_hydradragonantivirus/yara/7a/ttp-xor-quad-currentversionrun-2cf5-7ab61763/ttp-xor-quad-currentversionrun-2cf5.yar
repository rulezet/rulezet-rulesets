rule TTP_XOR_QUAD_CurrentVersionRun_2cf5 {
  strings:
    $key_2cf5 = { 7f 9a [2] 5b 94 [2] 70 b8 [2] 5e 9a [2] 4a 81 [2] 45 9b [2] 5b 86 [2] 59 87 [2] 42 81 [2] 5e 86 [2] 42 a9 }

  condition:
    any of them
}