rule TTP_XOR_QUAD_CurrentVersionRun_d768 {
  strings:
    $key_d768 = { 84 07 [2] a0 09 [2] 8b 25 [2] a5 07 [2] b1 1c [2] be 06 [2] a0 1b [2] a2 1a [2] b9 1c [2] a5 1b [2] b9 34 }

  condition:
    any of them
}