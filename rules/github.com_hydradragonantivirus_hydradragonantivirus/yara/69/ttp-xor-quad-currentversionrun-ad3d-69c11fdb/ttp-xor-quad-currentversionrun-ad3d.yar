rule TTP_XOR_QUAD_CurrentVersionRun_ad3d {
  strings:
    $key_ad3d = { fe 52 [2] da 5c [2] f1 70 [2] df 52 [2] cb 49 [2] c4 53 [2] da 4e [2] d8 4f [2] c3 49 [2] df 4e [2] c3 61 }

  condition:
    any of them
}