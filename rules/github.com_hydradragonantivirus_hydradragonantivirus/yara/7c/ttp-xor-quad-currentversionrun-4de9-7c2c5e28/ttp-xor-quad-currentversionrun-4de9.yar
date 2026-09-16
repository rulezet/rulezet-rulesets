rule TTP_XOR_QUAD_CurrentVersionRun_4de9 {
  strings:
    $key_4de9 = { 1e 86 [2] 3a 88 [2] 11 a4 [2] 3f 86 [2] 2b 9d [2] 24 87 [2] 3a 9a [2] 38 9b [2] 23 9d [2] 3f 9a [2] 23 b5 }

  condition:
    any of them
}