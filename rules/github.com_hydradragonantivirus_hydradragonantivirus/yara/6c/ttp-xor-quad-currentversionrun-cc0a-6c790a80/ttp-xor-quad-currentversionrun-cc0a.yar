rule TTP_XOR_QUAD_CurrentVersionRun_cc0a {
  strings:
    $key_cc0a = { 9f 65 [2] bb 6b [2] 90 47 [2] be 65 [2] aa 7e [2] a5 64 [2] bb 79 [2] b9 78 [2] a2 7e [2] be 79 [2] a2 56 }

  condition:
    any of them
}