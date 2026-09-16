rule TTP_XOR_QUAD_CurrentVersionRun_7875 {
  strings:
    $key_7875 = { 2b 1a [2] 0f 14 [2] 24 38 [2] 0a 1a [2] 1e 01 [2] 11 1b [2] 0f 06 [2] 0d 07 [2] 16 01 [2] 0a 06 [2] 16 29 }

  condition:
    any of them
}