rule TTP_XOR_QUAD_CurrentVersionRun_55e9 {
  strings:
    $key_55e9 = { 06 86 [2] 22 88 [2] 09 a4 [2] 27 86 [2] 33 9d [2] 3c 87 [2] 22 9a [2] 20 9b [2] 3b 9d [2] 27 9a [2] 3b b5 }

  condition:
    any of them
}