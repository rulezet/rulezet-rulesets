rule TTP_XOR_QUAD_CurrentVersionRun_cc02 {
  strings:
    $key_cc02 = { 9f 6d [2] bb 63 [2] 90 4f [2] be 6d [2] aa 76 [2] a5 6c [2] bb 71 [2] b9 70 [2] a2 76 [2] be 71 [2] a2 5e }

  condition:
    any of them
}