rule TTP_XOR_QUAD_CurrentVersionRun_cc22 {
  strings:
    $key_cc22 = { 9f 4d [2] bb 43 [2] 90 6f [2] be 4d [2] aa 56 [2] a5 4c [2] bb 51 [2] b9 50 [2] a2 56 [2] be 51 [2] a2 7e }

  condition:
    any of them
}