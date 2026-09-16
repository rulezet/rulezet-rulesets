rule TTP_XOR_QUAD_CurrentVersionRun_77fa {
  strings:
    $key_77fa = { 24 95 [2] 00 9b [2] 2b b7 [2] 05 95 [2] 11 8e [2] 1e 94 [2] 00 89 [2] 02 88 [2] 19 8e [2] 05 89 [2] 19 a6 }

  condition:
    any of them
}