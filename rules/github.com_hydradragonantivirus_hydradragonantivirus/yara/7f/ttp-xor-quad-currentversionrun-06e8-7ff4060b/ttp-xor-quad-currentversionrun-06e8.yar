rule TTP_XOR_QUAD_CurrentVersionRun_06e8 {
  strings:
    $key_06e8 = { 55 87 [2] 71 89 [2] 5a a5 [2] 74 87 [2] 60 9c [2] 6f 86 [2] 71 9b [2] 73 9a [2] 68 9c [2] 74 9b [2] 68 b4 }

  condition:
    any of them
}