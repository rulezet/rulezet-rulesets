rule TTP_XOR_QUAD_CurrentVersionRun_adbb {
  strings:
    $key_adbb = { fe d4 [2] da da [2] f1 f6 [2] df d4 [2] cb cf [2] c4 d5 [2] da c8 [2] d8 c9 [2] c3 cf [2] df c8 [2] c3 e7 }

  condition:
    any of them
}