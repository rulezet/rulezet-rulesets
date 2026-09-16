rule TTP_XOR_QUAD_CurrentVersionRun_65c2 {
  strings:
    $key_65c2 = { 36 ad [2] 12 a3 [2] 39 8f [2] 17 ad [2] 03 b6 [2] 0c ac [2] 12 b1 [2] 10 b0 [2] 0b b6 [2] 17 b1 [2] 0b 9e }

  condition:
    any of them
}