rule TTP_XOR_QUAD_CurrentVersionRun_c5f6 {
  strings:
    $key_c5f6 = { 96 99 [2] b2 97 [2] 99 bb [2] b7 99 [2] a3 82 [2] ac 98 [2] b2 85 [2] b0 84 [2] ab 82 [2] b7 85 [2] ab aa }

  condition:
    any of them
}