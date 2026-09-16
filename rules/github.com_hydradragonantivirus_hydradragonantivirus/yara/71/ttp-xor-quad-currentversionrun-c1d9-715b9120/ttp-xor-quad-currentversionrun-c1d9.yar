rule TTP_XOR_QUAD_CurrentVersionRun_c1d9 {
  strings:
    $key_c1d9 = { 92 b6 [2] b6 b8 [2] 9d 94 [2] b3 b6 [2] a7 ad [2] a8 b7 [2] b6 aa [2] b4 ab [2] af ad [2] b3 aa [2] af 85 }

  condition:
    any of them
}