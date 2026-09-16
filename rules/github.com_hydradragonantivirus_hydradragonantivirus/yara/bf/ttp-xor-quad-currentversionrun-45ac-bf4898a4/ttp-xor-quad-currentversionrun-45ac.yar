rule TTP_XOR_QUAD_CurrentVersionRun_45ac {
  strings:
    $key_45ac = { 16 c3 [2] 32 cd [2] 19 e1 [2] 37 c3 [2] 23 d8 [2] 2c c2 [2] 32 df [2] 30 de [2] 2b d8 [2] 37 df [2] 2b f0 }

  condition:
    any of them
}