rule TTP_XOR_QUAD_CurrentVersionRun_d9a7 {
  strings:
    $key_d9a7 = { 8a c8 [2] ae c6 [2] 85 ea [2] ab c8 [2] bf d3 [2] b0 c9 [2] ae d4 [2] ac d5 [2] b7 d3 [2] ab d4 [2] b7 fb }

  condition:
    any of them
}