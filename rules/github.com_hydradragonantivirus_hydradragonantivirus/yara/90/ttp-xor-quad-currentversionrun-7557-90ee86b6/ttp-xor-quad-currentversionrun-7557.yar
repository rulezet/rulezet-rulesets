rule TTP_XOR_QUAD_CurrentVersionRun_7557 {
  strings:
    $key_7557 = { 26 38 [2] 02 36 [2] 29 1a [2] 07 38 [2] 13 23 [2] 1c 39 [2] 02 24 [2] 00 25 [2] 1b 23 [2] 07 24 [2] 1b 0b }

  condition:
    any of them
}