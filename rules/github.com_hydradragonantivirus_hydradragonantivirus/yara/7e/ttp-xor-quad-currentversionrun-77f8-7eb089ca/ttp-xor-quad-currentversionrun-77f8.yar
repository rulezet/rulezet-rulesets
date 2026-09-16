rule TTP_XOR_QUAD_CurrentVersionRun_77f8 {
  strings:
    $key_77f8 = { 24 97 [2] 00 99 [2] 2b b5 [2] 05 97 [2] 11 8c [2] 1e 96 [2] 00 8b [2] 02 8a [2] 19 8c [2] 05 8b [2] 19 a4 }

  condition:
    any of them
}