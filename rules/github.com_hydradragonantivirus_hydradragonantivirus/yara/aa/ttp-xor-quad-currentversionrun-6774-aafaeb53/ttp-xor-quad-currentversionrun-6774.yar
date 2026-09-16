rule TTP_XOR_QUAD_CurrentVersionRun_6774 {
  strings:
    $key_6774 = { 34 1b [2] 10 15 [2] 3b 39 [2] 15 1b [2] 01 00 [2] 0e 1a [2] 10 07 [2] 12 06 [2] 09 00 [2] 15 07 [2] 09 28 }

  condition:
    any of them
}