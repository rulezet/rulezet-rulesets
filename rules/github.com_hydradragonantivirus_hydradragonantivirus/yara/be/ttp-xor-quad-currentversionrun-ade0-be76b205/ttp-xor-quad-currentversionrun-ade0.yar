rule TTP_XOR_QUAD_CurrentVersionRun_ade0 {
  strings:
    $key_ade0 = { fe 8f [2] da 81 [2] f1 ad [2] df 8f [2] cb 94 [2] c4 8e [2] da 93 [2] d8 92 [2] c3 94 [2] df 93 [2] c3 bc }

  condition:
    any of them
}