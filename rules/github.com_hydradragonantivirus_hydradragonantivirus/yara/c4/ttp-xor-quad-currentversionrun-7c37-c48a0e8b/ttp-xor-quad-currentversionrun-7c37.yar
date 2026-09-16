rule TTP_XOR_QUAD_CurrentVersionRun_7c37 {
  strings:
    $key_7c37 = { 2f 58 [2] 0b 56 [2] 20 7a [2] 0e 58 [2] 1a 43 [2] 15 59 [2] 0b 44 [2] 09 45 [2] 12 43 [2] 0e 44 [2] 12 6b }

  condition:
    any of them
}