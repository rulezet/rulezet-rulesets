rule TTP_XOR_QUAD_CurrentVersionRun_cc2f {
  strings:
    $key_cc2f = { 9f 40 [2] bb 4e [2] 90 62 [2] be 40 [2] aa 5b [2] a5 41 [2] bb 5c [2] b9 5d [2] a2 5b [2] be 5c [2] a2 73 }

  condition:
    any of them
}