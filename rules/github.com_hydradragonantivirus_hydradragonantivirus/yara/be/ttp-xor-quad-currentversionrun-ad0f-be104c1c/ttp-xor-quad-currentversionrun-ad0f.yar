rule TTP_XOR_QUAD_CurrentVersionRun_ad0f {
  strings:
    $key_ad0f = { fe 60 [2] da 6e [2] f1 42 [2] df 60 [2] cb 7b [2] c4 61 [2] da 7c [2] d8 7d [2] c3 7b [2] df 7c [2] c3 53 }

  condition:
    any of them
}