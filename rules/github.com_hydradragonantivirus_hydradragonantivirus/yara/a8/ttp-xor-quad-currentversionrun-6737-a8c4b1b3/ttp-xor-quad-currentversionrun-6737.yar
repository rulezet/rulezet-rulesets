rule TTP_XOR_QUAD_CurrentVersionRun_6737 {
  strings:
    $key_6737 = { 34 58 [2] 10 56 [2] 3b 7a [2] 15 58 [2] 01 43 [2] 0e 59 [2] 10 44 [2] 12 45 [2] 09 43 [2] 15 44 [2] 09 6b }

  condition:
    any of them
}