rule TTP_XOR_QUAD_CurrentVersionRun_d4c2 {
  strings:
    $key_d4c2 = { 87 ad [2] a3 a3 [2] 88 8f [2] a6 ad [2] b2 b6 [2] bd ac [2] a3 b1 [2] a1 b0 [2] ba b6 [2] a6 b1 [2] ba 9e }

  condition:
    any of them
}