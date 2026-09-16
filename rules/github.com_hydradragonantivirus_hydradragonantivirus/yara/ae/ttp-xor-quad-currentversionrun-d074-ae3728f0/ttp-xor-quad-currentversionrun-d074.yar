rule TTP_XOR_QUAD_CurrentVersionRun_d074 {
  strings:
    $key_d074 = { 83 1b [2] a7 15 [2] 8c 39 [2] a2 1b [2] b6 00 [2] b9 1a [2] a7 07 [2] a5 06 [2] be 00 [2] a2 07 [2] be 28 }

  condition:
    any of them
}