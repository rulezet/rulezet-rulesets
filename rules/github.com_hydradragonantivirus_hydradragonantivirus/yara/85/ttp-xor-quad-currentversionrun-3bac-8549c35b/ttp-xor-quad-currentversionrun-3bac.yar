rule TTP_XOR_QUAD_CurrentVersionRun_3bac {
  strings:
    $key_3bac = { 68 c3 [2] 4c cd [2] 67 e1 [2] 49 c3 [2] 5d d8 [2] 52 c2 [2] 4c df [2] 4e de [2] 55 d8 [2] 49 df [2] 55 f0 }

  condition:
    any of them
}