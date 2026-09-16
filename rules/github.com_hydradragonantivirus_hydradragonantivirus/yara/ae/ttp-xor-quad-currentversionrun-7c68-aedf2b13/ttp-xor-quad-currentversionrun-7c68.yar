rule TTP_XOR_QUAD_CurrentVersionRun_7c68 {
  strings:
    $key_7c68 = { 2f 07 [2] 0b 09 [2] 20 25 [2] 0e 07 [2] 1a 1c [2] 15 06 [2] 0b 1b [2] 09 1a [2] 12 1c [2] 0e 1b [2] 12 34 }

  condition:
    any of them
}