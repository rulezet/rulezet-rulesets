rule TTP_XOR_QUAD_CurrentVersionRun_d7c2 {
  strings:
    $key_d7c2 = { 84 ad [2] a0 a3 [2] 8b 8f [2] a5 ad [2] b1 b6 [2] be ac [2] a0 b1 [2] a2 b0 [2] b9 b6 [2] a5 b1 [2] b9 9e }

  condition:
    any of them
}