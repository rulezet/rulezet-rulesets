rule TTP_XOR_QUAD_CurrentVersionRun_5bab {
  strings:
    $key_5bab = { 08 c4 [2] 2c ca [2] 07 e6 [2] 29 c4 [2] 3d df [2] 32 c5 [2] 2c d8 [2] 2e d9 [2] 35 df [2] 29 d8 [2] 35 f7 }

  condition:
    any of them
}