rule TTP_XOR_QUAD_CurrentVersionRun_64c2 {
  strings:
    $key_64c2 = { 37 ad [2] 13 a3 [2] 38 8f [2] 16 ad [2] 02 b6 [2] 0d ac [2] 13 b1 [2] 11 b0 [2] 0a b6 [2] 16 b1 [2] 0a 9e }

  condition:
    any of them
}