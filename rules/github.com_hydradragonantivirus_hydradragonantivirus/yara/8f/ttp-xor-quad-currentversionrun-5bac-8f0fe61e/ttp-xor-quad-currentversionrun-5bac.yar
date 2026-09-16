rule TTP_XOR_QUAD_CurrentVersionRun_5bac {
  strings:
    $key_5bac = { 08 c3 [2] 2c cd [2] 07 e1 [2] 29 c3 [2] 3d d8 [2] 32 c2 [2] 2c df [2] 2e de [2] 35 d8 [2] 29 df [2] 35 f0 }

  condition:
    any of them
}