rule TTP_XOR_QUAD_CurrentVersionRun_cc5d {
  strings:
    $key_cc5d = { 9f 32 [2] bb 3c [2] 90 10 [2] be 32 [2] aa 29 [2] a5 33 [2] bb 2e [2] b9 2f [2] a2 29 [2] be 2e [2] a2 01 }

  condition:
    any of them
}