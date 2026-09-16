rule TTP_XOR_QUAD_CurrentVersionRun_7715 {
  strings:
    $key_7715 = { 24 7a [2] 00 74 [2] 2b 58 [2] 05 7a [2] 11 61 [2] 1e 7b [2] 00 66 [2] 02 67 [2] 19 61 [2] 05 66 [2] 19 49 }

  condition:
    any of them
}