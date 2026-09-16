rule TTP_XOR_QUAD_CurrentVersionRun_cc1b {
  strings:
    $key_cc1b = { 9f 74 [2] bb 7a [2] 90 56 [2] be 74 [2] aa 6f [2] a5 75 [2] bb 68 [2] b9 69 [2] a2 6f [2] be 68 [2] a2 47 }

  condition:
    any of them
}