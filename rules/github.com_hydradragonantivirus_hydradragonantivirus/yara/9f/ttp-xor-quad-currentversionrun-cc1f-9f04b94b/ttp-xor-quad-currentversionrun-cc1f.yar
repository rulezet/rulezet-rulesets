rule TTP_XOR_QUAD_CurrentVersionRun_cc1f {
  strings:
    $key_cc1f = { 9f 70 [2] bb 7e [2] 90 52 [2] be 70 [2] aa 6b [2] a5 71 [2] bb 6c [2] b9 6d [2] a2 6b [2] be 6c [2] a2 43 }

  condition:
    any of them
}