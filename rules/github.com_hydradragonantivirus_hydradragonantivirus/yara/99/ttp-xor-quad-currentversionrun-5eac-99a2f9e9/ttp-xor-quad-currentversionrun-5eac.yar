rule TTP_XOR_QUAD_CurrentVersionRun_5eac {
  strings:
    $key_5eac = { 0d c3 [2] 29 cd [2] 02 e1 [2] 2c c3 [2] 38 d8 [2] 37 c2 [2] 29 df [2] 2b de [2] 30 d8 [2] 2c df [2] 30 f0 }

  condition:
    any of them
}