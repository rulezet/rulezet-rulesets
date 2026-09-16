rule TTP_XOR_QUAD_CurrentVersionRun_7265 {
  strings:
    $key_7265 = { 21 0a [2] 05 04 [2] 2e 28 [2] 00 0a [2] 14 11 [2] 1b 0b [2] 05 16 [2] 07 17 [2] 1c 11 [2] 00 16 [2] 1c 39 }

  condition:
    any of them
}