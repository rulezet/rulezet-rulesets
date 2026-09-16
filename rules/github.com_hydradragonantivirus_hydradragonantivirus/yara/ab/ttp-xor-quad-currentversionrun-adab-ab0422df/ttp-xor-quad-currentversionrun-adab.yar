rule TTP_XOR_QUAD_CurrentVersionRun_adab {
  strings:
    $key_adab = { fe c4 [2] da ca [2] f1 e6 [2] df c4 [2] cb df [2] c4 c5 [2] da d8 [2] d8 d9 [2] c3 df [2] df d8 [2] c3 f7 }

  condition:
    any of them
}