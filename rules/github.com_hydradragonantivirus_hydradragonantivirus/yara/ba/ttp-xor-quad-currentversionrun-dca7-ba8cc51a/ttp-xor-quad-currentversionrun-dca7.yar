rule TTP_XOR_QUAD_CurrentVersionRun_dca7 {
  strings:
    $key_dca7 = { 8f c8 [2] ab c6 [2] 80 ea [2] ae c8 [2] ba d3 [2] b5 c9 [2] ab d4 [2] a9 d5 [2] b2 d3 [2] ae d4 [2] b2 fb }

  condition:
    any of them
}