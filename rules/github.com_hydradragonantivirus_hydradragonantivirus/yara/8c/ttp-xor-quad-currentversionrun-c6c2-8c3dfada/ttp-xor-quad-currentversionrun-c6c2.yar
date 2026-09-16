rule TTP_XOR_QUAD_CurrentVersionRun_c6c2 {
  strings:
    $key_c6c2 = { 95 ad [2] b1 a3 [2] 9a 8f [2] b4 ad [2] a0 b6 [2] af ac [2] b1 b1 [2] b3 b0 [2] a8 b6 [2] b4 b1 [2] a8 9e }

  condition:
    any of them
}