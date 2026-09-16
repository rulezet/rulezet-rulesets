rule TTP_XOR_QUAD_CurrentVersionRun_0c74 {
  strings:
    $key_0c74 = { 5f 1b [2] 7b 15 [2] 50 39 [2] 7e 1b [2] 6a 00 [2] 65 1a [2] 7b 07 [2] 79 06 [2] 62 00 [2] 7e 07 [2] 62 28 }

  condition:
    any of them
}