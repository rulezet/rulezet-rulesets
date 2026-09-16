rule TTP_XOR_QUAD_CurrentVersionRun_e9ad {
  strings:
    $key_e9ad = { ba c2 [2] 9e cc [2] b5 e0 [2] 9b c2 [2] 8f d9 [2] 80 c3 [2] 9e de [2] 9c df [2] 87 d9 [2] 9b de [2] 87 f1 }

  condition:
    any of them
}