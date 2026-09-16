rule TTP_XOR_QUAD_CurrentVersionRun_d775 {
  strings:
    $key_d775 = { 84 1a [2] a0 14 [2] 8b 38 [2] a5 1a [2] b1 01 [2] be 1b [2] a0 06 [2] a2 07 [2] b9 01 [2] a5 06 [2] b9 29 }

  condition:
    any of them
}