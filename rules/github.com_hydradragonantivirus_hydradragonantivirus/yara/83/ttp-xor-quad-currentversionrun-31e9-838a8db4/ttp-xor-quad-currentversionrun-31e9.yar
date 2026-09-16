rule TTP_XOR_QUAD_CurrentVersionRun_31e9 {
  strings:
    $key_31e9 = { 62 86 [2] 46 88 [2] 6d a4 [2] 43 86 [2] 57 9d [2] 58 87 [2] 46 9a [2] 44 9b [2] 5f 9d [2] 43 9a [2] 5f b5 }

  condition:
    any of them
}