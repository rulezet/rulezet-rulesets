rule TTP_XOR_QUAD_CurrentVersionRun_4bac {
  strings:
    $key_4bac = { 18 c3 [2] 3c cd [2] 17 e1 [2] 39 c3 [2] 2d d8 [2] 22 c2 [2] 3c df [2] 3e de [2] 25 d8 [2] 39 df [2] 25 f0 }

  condition:
    any of them
}