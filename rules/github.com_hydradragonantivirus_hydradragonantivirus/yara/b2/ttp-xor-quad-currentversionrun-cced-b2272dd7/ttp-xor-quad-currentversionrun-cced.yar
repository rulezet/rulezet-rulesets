rule TTP_XOR_QUAD_CurrentVersionRun_cced {
  strings:
    $key_cced = { 9f 82 [2] bb 8c [2] 90 a0 [2] be 82 [2] aa 99 [2] a5 83 [2] bb 9e [2] b9 9f [2] a2 99 [2] be 9e [2] a2 b1 }

  condition:
    any of them
}