rule TTP_XOR_QUAD_CurrentVersionRun_18e8 {
  strings:
    $key_18e8 = { 4b 87 [2] 6f 89 [2] 44 a5 [2] 6a 87 [2] 7e 9c [2] 71 86 [2] 6f 9b [2] 6d 9a [2] 76 9c [2] 6a 9b [2] 76 b4 }

  condition:
    any of them
}