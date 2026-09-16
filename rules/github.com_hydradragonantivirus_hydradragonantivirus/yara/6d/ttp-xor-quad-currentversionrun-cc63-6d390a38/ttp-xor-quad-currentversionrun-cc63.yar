rule TTP_XOR_QUAD_CurrentVersionRun_cc63 {
  strings:
    $key_cc63 = { 9f 0c [2] bb 02 [2] 90 2e [2] be 0c [2] aa 17 [2] a5 0d [2] bb 10 [2] b9 11 [2] a2 17 [2] be 10 [2] a2 3f }

  condition:
    any of them
}