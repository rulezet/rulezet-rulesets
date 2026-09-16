rule TTP_XOR_QUAD_CurrentVersionRun_77e4 {
  strings:
    $key_77e4 = { 24 8b [2] 00 85 [2] 2b a9 [2] 05 8b [2] 11 90 [2] 1e 8a [2] 00 97 [2] 02 96 [2] 19 90 [2] 05 97 [2] 19 b8 }

  condition:
    any of them
}