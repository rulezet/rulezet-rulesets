rule TTP_XOR_QUAD_CurrentVersionRun_28e9 {
  strings:
    $key_28e9 = { 7b 86 [2] 5f 88 [2] 74 a4 [2] 5a 86 [2] 4e 9d [2] 41 87 [2] 5f 9a [2] 5d 9b [2] 46 9d [2] 5a 9a [2] 46 b5 }

  condition:
    any of them
}