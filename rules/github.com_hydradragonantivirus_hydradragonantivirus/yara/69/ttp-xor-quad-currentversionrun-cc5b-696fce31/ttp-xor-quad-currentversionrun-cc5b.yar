rule TTP_XOR_QUAD_CurrentVersionRun_cc5b {
  strings:
    $key_cc5b = { 9f 34 [2] bb 3a [2] 90 16 [2] be 34 [2] aa 2f [2] a5 35 [2] bb 28 [2] b9 29 [2] a2 2f [2] be 28 [2] a2 07 }

  condition:
    any of them
}