rule TTP_XOR_QUAD_CurrentVersionRun_cc74 {
  strings:
    $key_cc74 = { 9f 1b [2] bb 15 [2] 90 39 [2] be 1b [2] aa 00 [2] a5 1a [2] bb 07 [2] b9 06 [2] a2 00 [2] be 07 [2] a2 28 }

  condition:
    any of them
}