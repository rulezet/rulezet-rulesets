rule TTP_XOR_QUAD_CurrentVersionRun_6bac {
  strings:
    $key_6bac = { 38 c3 [2] 1c cd [2] 37 e1 [2] 19 c3 [2] 0d d8 [2] 02 c2 [2] 1c df [2] 1e de [2] 05 d8 [2] 19 df [2] 05 f0 }

  condition:
    any of them
}