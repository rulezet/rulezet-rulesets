rule TTP_XOR_QUAD_CurrentVersionRun_ccf3 {
  strings:
    $key_ccf3 = { 9f 9c [2] bb 92 [2] 90 be [2] be 9c [2] aa 87 [2] a5 9d [2] bb 80 [2] b9 81 [2] a2 87 [2] be 80 [2] a2 af }

  condition:
    any of them
}