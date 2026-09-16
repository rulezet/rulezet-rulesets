rule TTP_XOR_QUAD_CurrentVersionRun_75c2 {
  strings:
    $key_75c2 = { 26 ad [2] 02 a3 [2] 29 8f [2] 07 ad [2] 13 b6 [2] 1c ac [2] 02 b1 [2] 00 b0 [2] 1b b6 [2] 07 b1 [2] 1b 9e }

  condition:
    any of them
}