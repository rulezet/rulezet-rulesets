rule TTP_XOR_QUAD_CurrentVersionRun_cc23 {
  strings:
    $key_cc23 = { 9f 4c [2] bb 42 [2] 90 6e [2] be 4c [2] aa 57 [2] a5 4d [2] bb 50 [2] b9 51 [2] a2 57 [2] be 50 [2] a2 7f }

  condition:
    any of them
}