rule TTP_XOR_QUAD_CurrentVersionRun_d075 {
  strings:
    $key_d075 = { 83 1a [2] a7 14 [2] 8c 38 [2] a2 1a [2] b6 01 [2] b9 1b [2] a7 06 [2] a5 07 [2] be 01 [2] a2 06 [2] be 29 }

  condition:
    any of them
}