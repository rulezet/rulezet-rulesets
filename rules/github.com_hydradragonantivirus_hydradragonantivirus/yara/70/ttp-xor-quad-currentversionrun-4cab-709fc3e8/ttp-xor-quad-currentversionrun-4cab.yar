rule TTP_XOR_QUAD_CurrentVersionRun_4cab {
  strings:
    $key_4cab = { 1f c4 [2] 3b ca [2] 10 e6 [2] 3e c4 [2] 2a df [2] 25 c5 [2] 3b d8 [2] 39 d9 [2] 22 df [2] 3e d8 [2] 22 f7 }

  condition:
    any of them
}