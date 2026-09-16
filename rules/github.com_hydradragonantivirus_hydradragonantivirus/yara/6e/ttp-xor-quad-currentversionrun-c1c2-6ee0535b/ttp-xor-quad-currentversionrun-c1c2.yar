rule TTP_XOR_QUAD_CurrentVersionRun_c1c2 {
  strings:
    $key_c1c2 = { 92 ad [2] b6 a3 [2] 9d 8f [2] b3 ad [2] a7 b6 [2] a8 ac [2] b6 b1 [2] b4 b0 [2] af b6 [2] b3 b1 [2] af 9e }

  condition:
    any of them
}