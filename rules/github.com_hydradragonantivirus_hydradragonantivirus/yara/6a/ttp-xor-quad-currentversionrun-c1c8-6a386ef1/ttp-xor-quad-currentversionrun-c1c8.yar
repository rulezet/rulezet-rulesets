rule TTP_XOR_QUAD_CurrentVersionRun_c1c8 {
  strings:
    $key_c1c8 = { 92 a7 [2] b6 a9 [2] 9d 85 [2] b3 a7 [2] a7 bc [2] a8 a6 [2] b6 bb [2] b4 ba [2] af bc [2] b3 bb [2] af 94 }

  condition:
    any of them
}