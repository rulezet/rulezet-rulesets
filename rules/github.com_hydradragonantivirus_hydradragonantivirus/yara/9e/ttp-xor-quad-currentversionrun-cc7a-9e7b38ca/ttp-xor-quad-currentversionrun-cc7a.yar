rule TTP_XOR_QUAD_CurrentVersionRun_cc7a {
  strings:
    $key_cc7a = { 9f 15 [2] bb 1b [2] 90 37 [2] be 15 [2] aa 0e [2] a5 14 [2] bb 09 [2] b9 08 [2] a2 0e [2] be 09 [2] a2 26 }

  condition:
    any of them
}