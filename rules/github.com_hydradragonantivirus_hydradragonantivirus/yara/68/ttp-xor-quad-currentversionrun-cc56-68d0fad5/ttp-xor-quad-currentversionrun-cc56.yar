rule TTP_XOR_QUAD_CurrentVersionRun_cc56 {
  strings:
    $key_cc56 = { 9f 39 [2] bb 37 [2] 90 1b [2] be 39 [2] aa 22 [2] a5 38 [2] bb 25 [2] b9 24 [2] a2 22 [2] be 25 [2] a2 0a }

  condition:
    any of them
}