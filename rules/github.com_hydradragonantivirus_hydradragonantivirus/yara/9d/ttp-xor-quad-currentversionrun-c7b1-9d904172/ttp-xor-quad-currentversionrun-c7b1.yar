rule TTP_XOR_QUAD_CurrentVersionRun_c7b1 {
  strings:
    $key_c7b1 = { 94 de [2] b0 d0 [2] 9b fc [2] b5 de [2] a1 c5 [2] ae df [2] b0 c2 [2] b2 c3 [2] a9 c5 [2] b5 c2 [2] a9 ed }

  condition:
    any of them
}