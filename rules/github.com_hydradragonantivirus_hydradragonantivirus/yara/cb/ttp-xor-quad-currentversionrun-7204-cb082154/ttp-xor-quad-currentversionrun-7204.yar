rule TTP_XOR_QUAD_CurrentVersionRun_7204 {
  strings:
    $key_7204 = { 21 6b [2] 05 65 [2] 2e 49 [2] 00 6b [2] 14 70 [2] 1b 6a [2] 05 77 [2] 07 76 [2] 1c 70 [2] 00 77 [2] 1c 58 }

  condition:
    any of them
}