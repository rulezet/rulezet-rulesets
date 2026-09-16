rule TTP_XOR_QUAD_CurrentVersionRun_c2ac {
  strings:
    $key_c2ac = { 91 c3 [2] b5 cd [2] 9e e1 [2] b0 c3 [2] a4 d8 [2] ab c2 [2] b5 df [2] b7 de [2] ac d8 [2] b0 df [2] ac f0 }

  condition:
    any of them
}