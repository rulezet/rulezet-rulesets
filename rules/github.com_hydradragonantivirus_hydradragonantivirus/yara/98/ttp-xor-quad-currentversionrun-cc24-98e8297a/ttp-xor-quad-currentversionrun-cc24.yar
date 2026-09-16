rule TTP_XOR_QUAD_CurrentVersionRun_cc24 {
  strings:
    $key_cc24 = { 9f 4b [2] bb 45 [2] 90 69 [2] be 4b [2] aa 50 [2] a5 4a [2] bb 57 [2] b9 56 [2] a2 50 [2] be 57 [2] a2 78 }

  condition:
    any of them
}