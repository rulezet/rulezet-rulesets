rule TTP_XOR_QUAD_CurrentVersionRun_ade1 {
  strings:
    $key_ade1 = { fe 8e [2] da 80 [2] f1 ac [2] df 8e [2] cb 95 [2] c4 8f [2] da 92 [2] d8 93 [2] c3 95 [2] df 92 [2] c3 bd }

  condition:
    any of them
}