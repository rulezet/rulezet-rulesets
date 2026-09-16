rule TTP_XOR_QUAD_CurrentVersionRun_77e8 {
  strings:
    $key_77e8 = { 24 87 [2] 00 89 [2] 2b a5 [2] 05 87 [2] 11 9c [2] 1e 86 [2] 00 9b [2] 02 9a [2] 19 9c [2] 05 9b [2] 19 b4 }

  condition:
    any of them
}