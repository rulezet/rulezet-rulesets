rule TTP_XOR_QUAD_CurrentVersionRun_d0c2 {
  strings:
    $key_d0c2 = { 83 ad [2] a7 a3 [2] 8c 8f [2] a2 ad [2] b6 b6 [2] b9 ac [2] a7 b1 [2] a5 b0 [2] be b6 [2] a2 b1 [2] be 9e }

  condition:
    any of them
}