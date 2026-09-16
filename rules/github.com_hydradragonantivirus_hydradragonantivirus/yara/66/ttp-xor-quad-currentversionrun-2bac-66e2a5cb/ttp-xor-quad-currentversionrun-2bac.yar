rule TTP_XOR_QUAD_CurrentVersionRun_2bac {
  strings:
    $key_2bac = { 78 c3 [2] 5c cd [2] 77 e1 [2] 59 c3 [2] 4d d8 [2] 42 c2 [2] 5c df [2] 5e de [2] 45 d8 [2] 59 df [2] 45 f0 }

  condition:
    any of them
}