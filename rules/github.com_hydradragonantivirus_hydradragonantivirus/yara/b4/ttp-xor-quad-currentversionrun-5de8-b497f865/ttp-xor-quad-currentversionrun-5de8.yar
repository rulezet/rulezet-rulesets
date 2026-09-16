rule TTP_XOR_QUAD_CurrentVersionRun_5de8 {
  strings:
    $key_5de8 = { 0e 87 [2] 2a 89 [2] 01 a5 [2] 2f 87 [2] 3b 9c [2] 34 86 [2] 2a 9b [2] 28 9a [2] 33 9c [2] 2f 9b [2] 33 b4 }

  condition:
    any of them
}