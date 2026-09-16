rule TTP_XOR_QUAD_CurrentVersionRun_7725 {
  strings:
    $key_7725 = { 24 4a [2] 00 44 [2] 2b 68 [2] 05 4a [2] 11 51 [2] 1e 4b [2] 00 56 [2] 02 57 [2] 19 51 [2] 05 56 [2] 19 79 }

  condition:
    any of them
}