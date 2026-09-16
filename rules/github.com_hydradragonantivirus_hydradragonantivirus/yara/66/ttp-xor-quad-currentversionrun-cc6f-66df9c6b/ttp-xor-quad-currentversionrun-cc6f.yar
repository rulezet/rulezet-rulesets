rule TTP_XOR_QUAD_CurrentVersionRun_cc6f {
  strings:
    $key_cc6f = { 9f 00 [2] bb 0e [2] 90 22 [2] be 00 [2] aa 1b [2] a5 01 [2] bb 1c [2] b9 1d [2] a2 1b [2] be 1c [2] a2 33 }

  condition:
    any of them
}