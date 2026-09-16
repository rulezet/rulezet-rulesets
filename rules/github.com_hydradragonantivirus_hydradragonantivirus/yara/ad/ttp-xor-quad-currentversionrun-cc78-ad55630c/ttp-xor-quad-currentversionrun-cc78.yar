rule TTP_XOR_QUAD_CurrentVersionRun_cc78 {
  strings:
    $key_cc78 = { 9f 17 [2] bb 19 [2] 90 35 [2] be 17 [2] aa 0c [2] a5 16 [2] bb 0b [2] b9 0a [2] a2 0c [2] be 0b [2] a2 24 }

  condition:
    any of them
}