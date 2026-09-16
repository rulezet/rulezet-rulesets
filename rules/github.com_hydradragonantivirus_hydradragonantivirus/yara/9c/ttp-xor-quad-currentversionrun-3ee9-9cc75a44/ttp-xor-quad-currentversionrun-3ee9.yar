rule TTP_XOR_QUAD_CurrentVersionRun_3ee9 {
  strings:
    $key_3ee9 = { 6d 86 [2] 49 88 [2] 62 a4 [2] 4c 86 [2] 58 9d [2] 57 87 [2] 49 9a [2] 4b 9b [2] 50 9d [2] 4c 9a [2] 50 b5 }

  condition:
    any of them
}