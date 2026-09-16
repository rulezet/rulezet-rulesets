rule TTP_XOR_QUAD_CurrentVersionRun_dfa6 {
  strings:
    $key_dfa6 = { 8c c9 [2] a8 c7 [2] 83 eb [2] ad c9 [2] b9 d2 [2] b6 c8 [2] a8 d5 [2] aa d4 [2] b1 d2 [2] ad d5 [2] b1 fa }

  condition:
    any of them
}