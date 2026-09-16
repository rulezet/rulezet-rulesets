rule TTP_XOR_QUAD_CurrentVersionRun_cc0c {
  strings:
    $key_cc0c = { 9f 63 [2] bb 6d [2] 90 41 [2] be 63 [2] aa 78 [2] a5 62 [2] bb 7f [2] b9 7e [2] a2 78 [2] be 7f [2] a2 50 }

  condition:
    any of them
}