rule TTP_XOR_QUAD_CurrentVersionRun_7237 {
  strings:
    $key_7237 = { 21 58 [2] 05 56 [2] 2e 7a [2] 00 58 [2] 14 43 [2] 1b 59 [2] 05 44 [2] 07 45 [2] 1c 43 [2] 00 44 [2] 1c 6b }

  condition:
    any of them
}