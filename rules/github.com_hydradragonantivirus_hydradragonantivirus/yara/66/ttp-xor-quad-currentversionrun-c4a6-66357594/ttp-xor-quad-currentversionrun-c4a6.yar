rule TTP_XOR_QUAD_CurrentVersionRun_c4a6 {
  strings:
    $key_c4a6 = { 97 c9 [2] b3 c7 [2] 98 eb [2] b6 c9 [2] a2 d2 [2] ad c8 [2] b3 d5 [2] b1 d4 [2] aa d2 [2] b6 d5 [2] aa fa }

  condition:
    any of them
}