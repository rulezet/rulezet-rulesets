rule TTP_XOR_QUAD_CurrentVersionRun_1674 {
  strings:
    $key_1674 = { 45 1b [2] 61 15 [2] 4a 39 [2] 64 1b [2] 70 00 [2] 7f 1a [2] 61 07 [2] 63 06 [2] 78 00 [2] 64 07 [2] 78 28 }

  condition:
    any of them
}