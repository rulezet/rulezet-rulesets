rule TTP_XOR_QUAD_CurrentVersionRun_55c2 {
  strings:
    $key_55c2 = { 06 ad [2] 22 a3 [2] 09 8f [2] 27 ad [2] 33 b6 [2] 3c ac [2] 22 b1 [2] 20 b0 [2] 3b b6 [2] 27 b1 [2] 3b 9e }

  condition:
    any of them
}