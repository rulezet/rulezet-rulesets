rule TTP_XOR_QUAD_CurrentVersionRun_cc57 {
  strings:
    $key_cc57 = { 9f 38 [2] bb 36 [2] 90 1a [2] be 38 [2] aa 23 [2] a5 39 [2] bb 24 [2] b9 25 [2] a2 23 [2] be 24 [2] a2 0b }

  condition:
    any of them
}