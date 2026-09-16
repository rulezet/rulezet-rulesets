rule TTP_XOR_QUAD_CurrentVersionRun_c3b6 {
  strings:
    $key_c3b6 = { 90 d9 [2] b4 d7 [2] 9f fb [2] b1 d9 [2] a5 c2 [2] aa d8 [2] b4 c5 [2] b6 c4 [2] ad c2 [2] b1 c5 [2] ad ea }

  condition:
    any of them
}