rule TTP_XOR_QUAD_CurrentVersionRun_d098 {
  strings:
    $key_d098 = { 83 f7 [2] a7 f9 [2] 8c d5 [2] a2 f7 [2] b6 ec [2] b9 f6 [2] a7 eb [2] a5 ea [2] be ec [2] a2 eb [2] be c4 }

  condition:
    any of them
}