rule TTP_XOR_QUAD_CurrentVersionRun_7bac {
  strings:
    $key_7bac = { 28 c3 [2] 0c cd [2] 27 e1 [2] 09 c3 [2] 1d d8 [2] 12 c2 [2] 0c df [2] 0e de [2] 15 d8 [2] 09 df [2] 15 f0 }

  condition:
    any of them
}