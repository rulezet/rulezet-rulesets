rule TTP_XOR_QUAD_CurrentVersionRun_cc15 {
  strings:
    $key_cc15 = { 9f 7a [2] bb 74 [2] 90 58 [2] be 7a [2] aa 61 [2] a5 7b [2] bb 66 [2] b9 67 [2] a2 61 [2] be 66 [2] a2 49 }

  condition:
    any of them
}