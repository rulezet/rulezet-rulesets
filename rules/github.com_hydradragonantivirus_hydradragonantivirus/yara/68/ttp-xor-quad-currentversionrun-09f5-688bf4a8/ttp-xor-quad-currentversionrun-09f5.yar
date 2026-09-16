rule TTP_XOR_QUAD_CurrentVersionRun_09f5 {
  strings:
    $key_09f5 = { 5a 9a [2] 7e 94 [2] 55 b8 [2] 7b 9a [2] 6f 81 [2] 60 9b [2] 7e 86 [2] 7c 87 [2] 67 81 [2] 7b 86 [2] 67 a9 }

  condition:
    any of them
}