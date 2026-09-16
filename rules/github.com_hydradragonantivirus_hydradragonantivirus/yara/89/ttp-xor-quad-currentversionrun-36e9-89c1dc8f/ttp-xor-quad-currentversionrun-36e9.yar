rule TTP_XOR_QUAD_CurrentVersionRun_36e9 {
  strings:
    $key_36e9 = { 65 86 [2] 41 88 [2] 6a a4 [2] 44 86 [2] 50 9d [2] 5f 87 [2] 41 9a [2] 43 9b [2] 58 9d [2] 44 9a [2] 58 b5 }

  condition:
    any of them
}