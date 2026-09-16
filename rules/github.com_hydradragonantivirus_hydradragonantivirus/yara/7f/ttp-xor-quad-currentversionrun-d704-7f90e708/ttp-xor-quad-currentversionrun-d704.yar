rule TTP_XOR_QUAD_CurrentVersionRun_d704 {
  strings:
    $key_d704 = { 84 6b [2] a0 65 [2] 8b 49 [2] a5 6b [2] b1 70 [2] be 6a [2] a0 77 [2] a2 76 [2] b9 70 [2] a5 77 [2] b9 58 }

  condition:
    any of them
}