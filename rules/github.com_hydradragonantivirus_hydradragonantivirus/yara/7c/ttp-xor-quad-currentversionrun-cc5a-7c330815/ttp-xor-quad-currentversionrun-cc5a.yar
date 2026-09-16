rule TTP_XOR_QUAD_CurrentVersionRun_cc5a {
  strings:
    $key_cc5a = { 9f 35 [2] bb 3b [2] 90 17 [2] be 35 [2] aa 2e [2] a5 34 [2] bb 29 [2] b9 28 [2] a2 2e [2] be 29 [2] a2 06 }

  condition:
    any of them
}