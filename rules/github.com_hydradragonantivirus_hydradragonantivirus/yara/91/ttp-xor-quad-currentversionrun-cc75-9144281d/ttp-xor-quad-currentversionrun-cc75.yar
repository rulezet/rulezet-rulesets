rule TTP_XOR_QUAD_CurrentVersionRun_cc75 {
  strings:
    $key_cc75 = { 9f 1a [2] bb 14 [2] 90 38 [2] be 1a [2] aa 01 [2] a5 1b [2] bb 06 [2] b9 07 [2] a2 01 [2] be 06 [2] a2 29 }

  condition:
    any of them
}