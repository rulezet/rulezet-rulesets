rule TTP_XOR_QUAD_CurrentVersionRun_54c2 {
  strings:
    $key_54c2 = { 07 ad [2] 23 a3 [2] 08 8f [2] 26 ad [2] 32 b6 [2] 3d ac [2] 23 b1 [2] 21 b0 [2] 3a b6 [2] 26 b1 [2] 3a 9e }

  condition:
    any of them
}