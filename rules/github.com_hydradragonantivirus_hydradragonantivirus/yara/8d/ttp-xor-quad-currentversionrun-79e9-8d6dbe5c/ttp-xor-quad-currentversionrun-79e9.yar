rule TTP_XOR_QUAD_CurrentVersionRun_79e9 {
  strings:
    $key_79e9 = { 2a 86 [2] 0e 88 [2] 25 a4 [2] 0b 86 [2] 1f 9d [2] 10 87 [2] 0e 9a [2] 0c 9b [2] 17 9d [2] 0b 9a [2] 17 b5 }

  condition:
    any of them
}