rule TTP_XOR_QUAD_CurrentVersionRun_d784 {
  strings:
    $key_d784 = { 84 eb [2] a0 e5 [2] 8b c9 [2] a5 eb [2] b1 f0 [2] be ea [2] a0 f7 [2] a2 f6 [2] b9 f0 [2] a5 f7 [2] b9 d8 }

  condition:
    any of them
}