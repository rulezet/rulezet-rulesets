rule TTP_XOR_QUAD_CurrentVersionRun_ad00 {
  strings:
    $key_ad00 = { fe 6f [2] da 61 [2] f1 4d [2] df 6f [2] cb 74 [2] c4 6e [2] da 73 [2] d8 72 [2] c3 74 [2] df 73 [2] c3 5c }

  condition:
    any of them
}