rule TTP_XOR_QUAD_CurrentVersionRun_1474 {
  strings:
    $key_1474 = { 47 1b [2] 63 15 [2] 48 39 [2] 66 1b [2] 72 00 [2] 7d 1a [2] 63 07 [2] 61 06 [2] 7a 00 [2] 66 07 [2] 7a 28 }

  condition:
    any of them
}