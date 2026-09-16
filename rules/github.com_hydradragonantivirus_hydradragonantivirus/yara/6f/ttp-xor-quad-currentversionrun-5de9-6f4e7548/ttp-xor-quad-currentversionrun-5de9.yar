rule TTP_XOR_QUAD_CurrentVersionRun_5de9 {
  strings:
    $key_5de9 = { 0e 86 [2] 2a 88 [2] 01 a4 [2] 2f 86 [2] 3b 9d [2] 34 87 [2] 2a 9a [2] 28 9b [2] 33 9d [2] 2f 9a [2] 33 b5 }

  condition:
    any of them
}