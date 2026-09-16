rule TTP_XOR_QUAD_CurrentVersionRun_d769 {
  strings:
    $key_d769 = { 84 06 [2] a0 08 [2] 8b 24 [2] a5 06 [2] b1 1d [2] be 07 [2] a0 1a [2] a2 1b [2] b9 1d [2] a5 1a [2] b9 35 }

  condition:
    any of them
}