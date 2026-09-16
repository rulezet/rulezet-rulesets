rule TTP_XOR_QUAD_CurrentVersionRun_cc40 {
  strings:
    $key_cc40 = { 9f 2f [2] bb 21 [2] 90 0d [2] be 2f [2] aa 34 [2] a5 2e [2] bb 33 [2] b9 32 [2] a2 34 [2] be 33 [2] a2 1c }

  condition:
    any of them
}