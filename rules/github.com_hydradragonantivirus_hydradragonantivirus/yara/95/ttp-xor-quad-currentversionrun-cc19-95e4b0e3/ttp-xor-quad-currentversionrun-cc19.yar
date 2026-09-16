rule TTP_XOR_QUAD_CurrentVersionRun_cc19 {
  strings:
    $key_cc19 = { 9f 76 [2] bb 78 [2] 90 54 [2] be 76 [2] aa 6d [2] a5 77 [2] bb 6a [2] b9 6b [2] a2 6d [2] be 6a [2] a2 45 }

  condition:
    any of them
}