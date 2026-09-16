rule TTP_XOR_QUAD_CurrentVersionRun_c457 {
  strings:
    $key_c457 = { 97 38 [2] b3 36 [2] 98 1a [2] b6 38 [2] a2 23 [2] ad 39 [2] b3 24 [2] b1 25 [2] aa 23 [2] b6 24 [2] aa 0b }

  condition:
    any of them
}