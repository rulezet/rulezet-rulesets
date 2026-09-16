rule TTP_XOR_QUAD_CurrentVersionRun_cc4f {
  strings:
    $key_cc4f = { 9f 20 [2] bb 2e [2] 90 02 [2] be 20 [2] aa 3b [2] a5 21 [2] bb 3c [2] b9 3d [2] a2 3b [2] be 3c [2] a2 13 }

  condition:
    any of them
}