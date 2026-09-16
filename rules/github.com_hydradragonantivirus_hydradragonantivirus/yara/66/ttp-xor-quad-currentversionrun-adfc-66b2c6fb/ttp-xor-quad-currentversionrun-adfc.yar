rule TTP_XOR_QUAD_CurrentVersionRun_adfc {
  strings:
    $key_adfc = { fe 93 [2] da 9d [2] f1 b1 [2] df 93 [2] cb 88 [2] c4 92 [2] da 8f [2] d8 8e [2] c3 88 [2] df 8f [2] c3 a0 }

  condition:
    any of them
}