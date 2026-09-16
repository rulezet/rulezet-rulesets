rule TTP_XOR_QUAD_CurrentVersionRun_d698 {
  strings:
    $key_d698 = { 85 f7 [2] a1 f9 [2] 8a d5 [2] a4 f7 [2] b0 ec [2] bf f6 [2] a1 eb [2] a3 ea [2] b8 ec [2] a4 eb [2] b8 c4 }

  condition:
    any of them
}