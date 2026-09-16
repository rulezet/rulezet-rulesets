rule TTP_XOR_QUAD_CurrentVersionRun_d9ad {
  strings:
    $key_d9ad = { 8a c2 [2] ae cc [2] 85 e0 [2] ab c2 [2] bf d9 [2] b0 c3 [2] ae de [2] ac df [2] b7 d9 [2] ab de [2] b7 f1 }

  condition:
    any of them
}