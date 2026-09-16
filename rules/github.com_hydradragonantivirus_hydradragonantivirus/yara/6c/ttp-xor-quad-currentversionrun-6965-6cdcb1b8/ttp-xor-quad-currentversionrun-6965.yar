rule TTP_XOR_QUAD_CurrentVersionRun_6965 {
  strings:
    $key_6965 = { 3a 0a [2] 1e 04 [2] 35 28 [2] 1b 0a [2] 0f 11 [2] 00 0b [2] 1e 16 [2] 1c 17 [2] 07 11 [2] 1b 16 [2] 07 39 }

  condition:
    any of them
}