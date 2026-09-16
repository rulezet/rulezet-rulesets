rule TTP_XOR_QUAD_CurrentVersionRun_7674 {
  strings:
    $key_7674 = { 25 1b [2] 01 15 [2] 2a 39 [2] 04 1b [2] 10 00 [2] 1f 1a [2] 01 07 [2] 03 06 [2] 18 00 [2] 04 07 [2] 18 28 }

  condition:
    any of them
}