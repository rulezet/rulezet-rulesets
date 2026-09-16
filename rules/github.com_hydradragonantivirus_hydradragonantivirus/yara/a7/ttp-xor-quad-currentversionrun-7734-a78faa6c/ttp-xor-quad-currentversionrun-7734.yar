rule TTP_XOR_QUAD_CurrentVersionRun_7734 {
  strings:
    $key_7734 = { 24 5b [2] 00 55 [2] 2b 79 [2] 05 5b [2] 11 40 [2] 1e 5a [2] 00 47 [2] 02 46 [2] 19 40 [2] 05 47 [2] 19 68 }

  condition:
    any of them
}