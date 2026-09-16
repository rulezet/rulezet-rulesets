rule TTP_XOR_QUAD_CurrentVersionRun_cc73 {
  strings:
    $key_cc73 = { 9f 1c [2] bb 12 [2] 90 3e [2] be 1c [2] aa 07 [2] a5 1d [2] bb 00 [2] b9 01 [2] a2 07 [2] be 00 [2] a2 2f }

  condition:
    any of them
}