rule TTP_XOR_QUAD_CurrentVersionRun_dfcf {
  strings:
    $key_dfcf = { 8c a0 [2] a8 ae [2] 83 82 [2] ad a0 [2] b9 bb [2] b6 a1 [2] a8 bc [2] aa bd [2] b1 bb [2] ad bc [2] b1 93 }

  condition:
    any of them
}