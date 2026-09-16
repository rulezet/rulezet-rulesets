rule TTP_XOR_QUAD_CurrentVersionRun_77e9 {
  strings:
    $key_77e9 = { 24 86 [2] 00 88 [2] 2b a4 [2] 05 86 [2] 11 9d [2] 1e 87 [2] 00 9a [2] 02 9b [2] 19 9d [2] 05 9a [2] 19 b5 }

  condition:
    any of them
}