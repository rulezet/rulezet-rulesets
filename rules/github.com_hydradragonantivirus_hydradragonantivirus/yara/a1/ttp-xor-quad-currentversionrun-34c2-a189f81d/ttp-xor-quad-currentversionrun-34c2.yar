rule TTP_XOR_QUAD_CurrentVersionRun_34c2 {
  strings:
    $key_34c2 = { 67 ad [2] 43 a3 [2] 68 8f [2] 46 ad [2] 52 b6 [2] 5d ac [2] 43 b1 [2] 41 b0 [2] 5a b6 [2] 46 b1 [2] 5a 9e }

  condition:
    any of them
}