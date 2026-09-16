rule TTP_XOR_QUAD_CurrentVersionRun_c5c2 {
  strings:
    $key_c5c2 = { 96 ad [2] b2 a3 [2] 99 8f [2] b7 ad [2] a3 b6 [2] ac ac [2] b2 b1 [2] b0 b0 [2] ab b6 [2] b7 b1 [2] ab 9e }

  condition:
    any of them
}