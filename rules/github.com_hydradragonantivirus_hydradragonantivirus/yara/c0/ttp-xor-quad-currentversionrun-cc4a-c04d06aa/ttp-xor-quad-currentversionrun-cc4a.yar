rule TTP_XOR_QUAD_CurrentVersionRun_cc4a {
  strings:
    $key_cc4a = { 9f 25 [2] bb 2b [2] 90 07 [2] be 25 [2] aa 3e [2] a5 24 [2] bb 39 [2] b9 38 [2] a2 3e [2] be 39 [2] a2 16 }

  condition:
    any of them
}