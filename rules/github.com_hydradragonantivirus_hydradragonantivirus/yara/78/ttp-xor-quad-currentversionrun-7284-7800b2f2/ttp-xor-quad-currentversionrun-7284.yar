rule TTP_XOR_QUAD_CurrentVersionRun_7284 {
  strings:
    $key_7284 = { 21 eb [2] 05 e5 [2] 2e c9 [2] 00 eb [2] 14 f0 [2] 1b ea [2] 05 f7 [2] 07 f6 [2] 1c f0 [2] 00 f7 [2] 1c d8 }

  condition:
    any of them
}