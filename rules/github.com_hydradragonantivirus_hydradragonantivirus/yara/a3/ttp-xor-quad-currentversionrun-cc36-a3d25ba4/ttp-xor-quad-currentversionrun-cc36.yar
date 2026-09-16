rule TTP_XOR_QUAD_CurrentVersionRun_cc36 {
  strings:
    $key_cc36 = { 9f 59 [2] bb 57 [2] 90 7b [2] be 59 [2] aa 42 [2] a5 58 [2] bb 45 [2] b9 44 [2] a2 42 [2] be 45 [2] a2 6a }

  condition:
    any of them
}