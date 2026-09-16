rule TTP_XOR_QUAD_CurrentVersionRun_c4cf {
  strings:
    $key_c4cf = { 97 a0 [2] b3 ae [2] 98 82 [2] b6 a0 [2] a2 bb [2] ad a1 [2] b3 bc [2] b1 bd [2] aa bb [2] b6 bc [2] aa 93 }

  condition:
    any of them
}