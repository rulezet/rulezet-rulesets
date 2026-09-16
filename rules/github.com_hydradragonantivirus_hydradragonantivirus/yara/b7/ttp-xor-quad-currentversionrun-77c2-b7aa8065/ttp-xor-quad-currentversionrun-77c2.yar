rule TTP_XOR_QUAD_CurrentVersionRun_77c2 {
  strings:
    $key_77c2 = { 24 ad [2] 00 a3 [2] 2b 8f [2] 05 ad [2] 11 b6 [2] 1e ac [2] 00 b1 [2] 02 b0 [2] 19 b6 [2] 05 b1 [2] 19 9e }

  condition:
    any of them
}