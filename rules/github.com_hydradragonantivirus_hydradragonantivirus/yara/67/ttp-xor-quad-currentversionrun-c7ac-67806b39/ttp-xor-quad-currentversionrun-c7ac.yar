rule TTP_XOR_QUAD_CurrentVersionRun_c7ac {
  strings:
    $key_c7ac = { 94 c3 [2] b0 cd [2] 9b e1 [2] b5 c3 [2] a1 d8 [2] ae c2 [2] b0 df [2] b2 de [2] a9 d8 [2] b5 df [2] a9 f0 }

  condition:
    any of them
}