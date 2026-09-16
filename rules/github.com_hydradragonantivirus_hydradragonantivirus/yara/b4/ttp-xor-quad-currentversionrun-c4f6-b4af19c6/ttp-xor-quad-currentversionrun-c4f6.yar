rule TTP_XOR_QUAD_CurrentVersionRun_c4f6 {
  strings:
    $key_c4f6 = { 97 99 [2] b3 97 [2] 98 bb [2] b6 99 [2] a2 82 [2] ad 98 [2] b3 85 [2] b1 84 [2] aa 82 [2] b6 85 [2] aa aa }

  condition:
    any of them
}