rule TTP_XOR_QUAD_CurrentVersionRun_cc41 {
  strings:
    $key_cc41 = { 9f 2e [2] bb 20 [2] 90 0c [2] be 2e [2] aa 35 [2] a5 2f [2] bb 32 [2] b9 33 [2] a2 35 [2] be 32 [2] a2 1d }

  condition:
    any of them
}