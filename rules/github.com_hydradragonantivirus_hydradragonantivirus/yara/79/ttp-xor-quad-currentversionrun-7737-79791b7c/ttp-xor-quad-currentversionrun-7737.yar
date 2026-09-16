rule TTP_XOR_QUAD_CurrentVersionRun_7737 {
  strings:
    $key_7737 = { 24 58 [2] 00 56 [2] 2b 7a [2] 05 58 [2] 11 43 [2] 1e 59 [2] 00 44 [2] 02 45 [2] 19 43 [2] 05 44 [2] 19 6b }

  condition:
    any of them
}