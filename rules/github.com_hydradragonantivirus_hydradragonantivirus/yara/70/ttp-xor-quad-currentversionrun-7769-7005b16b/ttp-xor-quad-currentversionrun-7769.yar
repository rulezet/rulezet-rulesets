rule TTP_XOR_QUAD_CurrentVersionRun_7769 {
  strings:
    $key_7769 = { 24 06 [2] 00 08 [2] 2b 24 [2] 05 06 [2] 11 1d [2] 1e 07 [2] 00 1a [2] 02 1b [2] 19 1d [2] 05 1a [2] 19 35 }

  condition:
    any of them
}