rule TTP_XOR_QUAD_CurrentVersionRun_ccf4 {
  strings:
    $key_ccf4 = { 9f 9b [2] bb 95 [2] 90 b9 [2] be 9b [2] aa 80 [2] a5 9a [2] bb 87 [2] b9 86 [2] a2 80 [2] be 87 [2] a2 a8 }

  condition:
    any of them
}