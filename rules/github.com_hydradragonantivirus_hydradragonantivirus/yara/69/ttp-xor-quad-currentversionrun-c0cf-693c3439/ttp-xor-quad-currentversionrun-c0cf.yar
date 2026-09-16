rule TTP_XOR_QUAD_CurrentVersionRun_c0cf {
  strings:
    $key_c0cf = { 93 a0 [2] b7 ae [2] 9c 82 [2] b2 a0 [2] a6 bb [2] a9 a1 [2] b7 bc [2] b5 bd [2] ae bb [2] b2 bc [2] ae 93 }

  condition:
    any of them
}