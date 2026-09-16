rule TTP_XOR_QUAD_CurrentVersionRun_d657 {
  strings:
    $key_d657 = { 85 38 [2] a1 36 [2] 8a 1a [2] a4 38 [2] b0 23 [2] bf 39 [2] a1 24 [2] a3 25 [2] b8 23 [2] a4 24 [2] b8 0b }

  condition:
    any of them
}