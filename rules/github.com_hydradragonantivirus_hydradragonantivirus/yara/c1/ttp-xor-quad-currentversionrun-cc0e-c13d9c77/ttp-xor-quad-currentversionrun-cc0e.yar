rule TTP_XOR_QUAD_CurrentVersionRun_cc0e {
  strings:
    $key_cc0e = { 9f 61 [2] bb 6f [2] 90 43 [2] be 61 [2] aa 7a [2] a5 60 [2] bb 7d [2] b9 7c [2] a2 7a [2] be 7d [2] a2 52 }

  condition:
    any of them
}