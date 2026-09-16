rule TTP_XOR_QUAD_CurrentVersionRun_fcab {
  strings:
    $key_fcab = { af c4 [2] 8b ca [2] a0 e6 [2] 8e c4 [2] 9a df [2] 95 c5 [2] 8b d8 [2] 89 d9 [2] 92 df [2] 8e d8 [2] 92 f7 }

  condition:
    any of them
}