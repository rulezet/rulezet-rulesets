rule TTP_XOR_QUAD_CurrentVersionRun_d774 {
  strings:
    $key_d774 = { 84 1b [2] a0 15 [2] 8b 39 [2] a5 1b [2] b1 00 [2] be 1a [2] a0 07 [2] a2 06 [2] b9 00 [2] a5 07 [2] b9 28 }

  condition:
    any of them
}