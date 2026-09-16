rule TTP_XOR_QUAD_CurrentVersionRun_e4c2 {
  strings:
    $key_e4c2 = { b7 ad [2] 93 a3 [2] b8 8f [2] 96 ad [2] 82 b6 [2] 8d ac [2] 93 b1 [2] 91 b0 [2] 8a b6 [2] 96 b1 [2] 8a 9e }

  condition:
    any of them
}