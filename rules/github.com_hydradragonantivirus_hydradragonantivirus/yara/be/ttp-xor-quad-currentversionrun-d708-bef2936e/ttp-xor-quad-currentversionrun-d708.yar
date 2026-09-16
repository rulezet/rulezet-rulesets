rule TTP_XOR_QUAD_CurrentVersionRun_d708 {
  strings:
    $key_d708 = { 84 67 [2] a0 69 [2] 8b 45 [2] a5 67 [2] b1 7c [2] be 66 [2] a0 7b [2] a2 7a [2] b9 7c [2] a5 7b [2] b9 54 }

  condition:
    any of them
}