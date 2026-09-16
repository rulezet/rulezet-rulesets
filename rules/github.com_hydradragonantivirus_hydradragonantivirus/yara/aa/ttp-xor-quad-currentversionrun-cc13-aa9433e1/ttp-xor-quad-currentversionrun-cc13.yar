rule TTP_XOR_QUAD_CurrentVersionRun_cc13 {
  strings:
    $key_cc13 = { 9f 7c [2] bb 72 [2] 90 5e [2] be 7c [2] aa 67 [2] a5 7d [2] bb 60 [2] b9 61 [2] a2 67 [2] be 60 [2] a2 4f }

  condition:
    any of them
}