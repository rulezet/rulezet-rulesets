rule TTP_XOR_QUAD_CurrentVersionRun_7264 {
  strings:
    $key_7264 = { 21 0b [2] 05 05 [2] 2e 29 [2] 00 0b [2] 14 10 [2] 1b 0a [2] 05 17 [2] 07 16 [2] 1c 10 [2] 00 17 [2] 1c 38 }

  condition:
    any of them
}