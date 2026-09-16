rule TTP_XOR_QUAD_CurrentVersionRun_adeb {
  strings:
    $key_adeb = { fe 84 [2] da 8a [2] f1 a6 [2] df 84 [2] cb 9f [2] c4 85 [2] da 98 [2] d8 99 [2] c3 9f [2] df 98 [2] c3 b7 }

  condition:
    any of them
}