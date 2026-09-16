rule TTP_XOR_QUAD_CurrentVersionRun_cc12 {
  strings:
    $key_cc12 = { 9f 7d [2] bb 73 [2] 90 5f [2] be 7d [2] aa 66 [2] a5 7c [2] bb 61 [2] b9 60 [2] a2 66 [2] be 61 [2] a2 4e }

  condition:
    any of them
}