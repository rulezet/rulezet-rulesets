rule TTP_XOR_QUAD_CurrentVersionRun_7cf5 {
  strings:
    $key_7cf5 = { 2f 9a [2] 0b 94 [2] 20 b8 [2] 0e 9a [2] 1a 81 [2] 15 9b [2] 0b 86 [2] 09 87 [2] 12 81 [2] 0e 86 [2] 12 a9 }

  condition:
    any of them
}