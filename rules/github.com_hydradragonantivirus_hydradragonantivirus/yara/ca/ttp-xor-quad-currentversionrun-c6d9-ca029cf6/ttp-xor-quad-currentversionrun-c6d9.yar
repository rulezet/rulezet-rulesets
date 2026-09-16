rule TTP_XOR_QUAD_CurrentVersionRun_c6d9 {
  strings:
    $key_c6d9 = { 95 b6 [2] b1 b8 [2] 9a 94 [2] b4 b6 [2] a0 ad [2] af b7 [2] b1 aa [2] b3 ab [2] a8 ad [2] b4 aa [2] a8 85 }

  condition:
    any of them
}