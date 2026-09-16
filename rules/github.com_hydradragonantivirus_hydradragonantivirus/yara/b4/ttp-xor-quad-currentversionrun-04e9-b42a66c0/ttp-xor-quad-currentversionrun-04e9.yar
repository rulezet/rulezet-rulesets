rule TTP_XOR_QUAD_CurrentVersionRun_04e9 {
  strings:
    $key_04e9 = { 57 86 [2] 73 88 [2] 58 a4 [2] 76 86 [2] 62 9d [2] 6d 87 [2] 73 9a [2] 71 9b [2] 6a 9d [2] 76 9a [2] 6a b5 }

  condition:
    any of them
}