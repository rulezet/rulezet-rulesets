rule TTP_XOR_QUAD_CurrentVersionRun_aaba {
  strings:
    $key_aaba = { f9 d5 [2] dd db [2] f6 f7 [2] d8 d5 [2] cc ce [2] c3 d4 [2] dd c9 [2] df c8 [2] c4 ce [2] d8 c9 [2] c4 e6 }

  condition:
    any of them
}