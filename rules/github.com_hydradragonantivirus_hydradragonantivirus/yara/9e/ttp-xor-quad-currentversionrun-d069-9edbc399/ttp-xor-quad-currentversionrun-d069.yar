rule TTP_XOR_QUAD_CurrentVersionRun_d069 {
  strings:
    $key_d069 = { 83 06 [2] a7 08 [2] 8c 24 [2] a2 06 [2] b6 1d [2] b9 07 [2] a7 1a [2] a5 1b [2] be 1d [2] a2 1a [2] be 35 }

  condition:
    any of them
}