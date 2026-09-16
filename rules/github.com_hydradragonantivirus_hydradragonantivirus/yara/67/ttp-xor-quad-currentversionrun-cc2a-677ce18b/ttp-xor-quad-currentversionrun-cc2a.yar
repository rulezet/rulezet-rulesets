rule TTP_XOR_QUAD_CurrentVersionRun_cc2a {
  strings:
    $key_cc2a = { 9f 45 [2] bb 4b [2] 90 67 [2] be 45 [2] aa 5e [2] a5 44 [2] bb 59 [2] b9 58 [2] a2 5e [2] be 59 [2] a2 76 }

  condition:
    any of them
}