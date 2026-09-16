rule TTP_XOR_QUAD_CurrentVersionRun_cc7d {
  strings:
    $key_cc7d = { 9f 12 [2] bb 1c [2] 90 30 [2] be 12 [2] aa 09 [2] a5 13 [2] bb 0e [2] b9 0f [2] a2 09 [2] be 0e [2] a2 21 }

  condition:
    any of them
}