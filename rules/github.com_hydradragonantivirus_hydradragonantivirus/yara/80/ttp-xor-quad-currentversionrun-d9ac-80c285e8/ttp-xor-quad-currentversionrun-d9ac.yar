rule TTP_XOR_QUAD_CurrentVersionRun_d9ac {
  strings:
    $key_d9ac = { 8a c3 [2] ae cd [2] 85 e1 [2] ab c3 [2] bf d8 [2] b0 c2 [2] ae df [2] ac de [2] b7 d8 [2] ab df [2] b7 f0 }

  condition:
    any of them
}