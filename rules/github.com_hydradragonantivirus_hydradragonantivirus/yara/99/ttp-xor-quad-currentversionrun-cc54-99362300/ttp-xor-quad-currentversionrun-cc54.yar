rule TTP_XOR_QUAD_CurrentVersionRun_cc54 {
  strings:
    $key_cc54 = { 9f 3b [2] bb 35 [2] 90 19 [2] be 3b [2] aa 20 [2] a5 3a [2] bb 27 [2] b9 26 [2] a2 20 [2] be 27 [2] a2 08 }

  condition:
    any of them
}