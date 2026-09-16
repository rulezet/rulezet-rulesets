rule TTP_XOR_QUAD_CurrentVersionRun_7224 {
  strings:
    $key_7224 = { 21 4b [2] 05 45 [2] 2e 69 [2] 00 4b [2] 14 50 [2] 1b 4a [2] 05 57 [2] 07 56 [2] 1c 50 [2] 00 57 [2] 1c 78 }

  condition:
    any of them
}