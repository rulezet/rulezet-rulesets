rule TTP_XOR_QUAD_CurrentVersionRun_7874 {
  strings:
    $key_7874 = { 2b 1b [2] 0f 15 [2] 24 39 [2] 0a 1b [2] 1e 00 [2] 11 1a [2] 0f 07 [2] 0d 06 [2] 16 00 [2] 0a 07 [2] 16 28 }

  condition:
    any of them
}