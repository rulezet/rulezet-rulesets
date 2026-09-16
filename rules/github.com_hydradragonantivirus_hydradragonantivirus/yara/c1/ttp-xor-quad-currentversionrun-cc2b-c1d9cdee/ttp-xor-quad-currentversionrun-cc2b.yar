rule TTP_XOR_QUAD_CurrentVersionRun_cc2b {
  strings:
    $key_cc2b = { 9f 44 [2] bb 4a [2] 90 66 [2] be 44 [2] aa 5f [2] a5 45 [2] bb 58 [2] b9 59 [2] a2 5f [2] be 58 [2] a2 77 }

  condition:
    any of them
}