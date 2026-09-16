rule TTP_XOR_QUAD_CurrentVersionRun_cc2e {
  strings:
    $key_cc2e = { 9f 41 [2] bb 4f [2] 90 63 [2] be 41 [2] aa 5a [2] a5 40 [2] bb 5d [2] b9 5c [2] a2 5a [2] be 5d [2] a2 72 }

  condition:
    any of them
}