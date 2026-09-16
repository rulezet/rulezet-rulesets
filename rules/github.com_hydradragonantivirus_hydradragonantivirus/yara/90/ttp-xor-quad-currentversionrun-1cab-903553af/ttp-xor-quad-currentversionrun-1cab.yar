rule TTP_XOR_QUAD_CurrentVersionRun_1cab {
  strings:
    $key_1cab = { 4f c4 [2] 6b ca [2] 40 e6 [2] 6e c4 [2] 7a df [2] 75 c5 [2] 6b d8 [2] 69 d9 [2] 72 df [2] 6e d8 [2] 72 f7 }

  condition:
    any of them
}