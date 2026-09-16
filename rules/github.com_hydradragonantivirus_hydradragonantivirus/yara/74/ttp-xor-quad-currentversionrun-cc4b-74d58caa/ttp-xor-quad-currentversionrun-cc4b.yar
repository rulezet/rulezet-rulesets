rule TTP_XOR_QUAD_CurrentVersionRun_cc4b {
  strings:
    $key_cc4b = { 9f 24 [2] bb 2a [2] 90 06 [2] be 24 [2] aa 3f [2] a5 25 [2] bb 38 [2] b9 39 [2] a2 3f [2] be 38 [2] a2 17 }

  condition:
    any of them
}