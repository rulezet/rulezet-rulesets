rule TTP_XOR_QUAD_CurrentVersionRun_cc48 {
  strings:
    $key_cc48 = { 9f 27 [2] bb 29 [2] 90 05 [2] be 27 [2] aa 3c [2] a5 26 [2] bb 3b [2] b9 3a [2] a2 3c [2] be 3b [2] a2 14 }

  condition:
    any of them
}