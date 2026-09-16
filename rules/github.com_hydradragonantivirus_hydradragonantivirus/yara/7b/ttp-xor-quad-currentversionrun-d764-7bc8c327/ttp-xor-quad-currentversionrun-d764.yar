rule TTP_XOR_QUAD_CurrentVersionRun_d764 {
  strings:
    $key_d764 = { 84 0b [2] a0 05 [2] 8b 29 [2] a5 0b [2] b1 10 [2] be 0a [2] a0 17 [2] a2 16 [2] b9 10 [2] a5 17 [2] b9 38 }

  condition:
    any of them
}