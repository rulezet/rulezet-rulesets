rule TTP_XOR_QUAD_CurrentVersionRun_64e8 {
  strings:
    $key_64e8 = { 37 87 [2] 13 89 [2] 38 a5 [2] 16 87 [2] 02 9c [2] 0d 86 [2] 13 9b [2] 11 9a [2] 0a 9c [2] 16 9b [2] 0a b4 }

  condition:
    any of them
}