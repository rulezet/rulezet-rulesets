rule TTP_XOR_QUAD_CurrentVersionRun_6874 {
  strings:
    $key_6874 = { 3b 1b [2] 1f 15 [2] 34 39 [2] 1a 1b [2] 0e 00 [2] 01 1a [2] 1f 07 [2] 1d 06 [2] 06 00 [2] 1a 07 [2] 06 28 }

  condition:
    any of them
}