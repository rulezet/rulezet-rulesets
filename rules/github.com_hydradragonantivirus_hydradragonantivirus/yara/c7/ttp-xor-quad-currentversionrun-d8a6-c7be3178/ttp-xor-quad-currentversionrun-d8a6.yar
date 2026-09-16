rule TTP_XOR_QUAD_CurrentVersionRun_d8a6 {
  strings:
    $key_d8a6 = { 8b c9 [2] af c7 [2] 84 eb [2] aa c9 [2] be d2 [2] b1 c8 [2] af d5 [2] ad d4 [2] b6 d2 [2] aa d5 [2] b6 fa }

  condition:
    any of them
}