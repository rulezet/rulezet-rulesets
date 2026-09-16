rule TTP_XOR_QUAD_CurrentVersionRun_ccff {
  strings:
    $key_ccff = { 9f 90 [2] bb 9e [2] 90 b2 [2] be 90 [2] aa 8b [2] a5 91 [2] bb 8c [2] b9 8d [2] a2 8b [2] be 8c [2] a2 a3 }

  condition:
    any of them
}