rule TTP_XOR_QUAD_CurrentVersionRun_7cab {
  strings:
    $key_7cab = { 2f c4 [2] 0b ca [2] 20 e6 [2] 0e c4 [2] 1a df [2] 15 c5 [2] 0b d8 [2] 09 d9 [2] 12 df [2] 0e d8 [2] 12 f7 }

  condition:
    any of them
}