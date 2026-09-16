rule TTP_XOR_QUAD_CurrentVersionRun_d9a6 {
  strings:
    $key_d9a6 = { 8a c9 [2] ae c7 [2] 85 eb [2] ab c9 [2] bf d2 [2] b0 c8 [2] ae d5 [2] ac d4 [2] b7 d2 [2] ab d5 [2] b7 fa }

  condition:
    any of them
}