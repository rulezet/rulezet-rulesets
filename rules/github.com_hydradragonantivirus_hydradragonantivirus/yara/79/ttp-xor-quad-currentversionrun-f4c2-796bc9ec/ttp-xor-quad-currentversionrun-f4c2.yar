rule TTP_XOR_QUAD_CurrentVersionRun_f4c2 {
  strings:
    $key_f4c2 = { a7 ad [2] 83 a3 [2] a8 8f [2] 86 ad [2] 92 b6 [2] 9d ac [2] 83 b1 [2] 81 b0 [2] 9a b6 [2] 86 b1 [2] 9a 9e }

  condition:
    any of them
}