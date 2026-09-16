rule TTP_XOR_QUAD_CurrentVersionRun_ade3 {
  strings:
    $key_ade3 = { fe 8c [2] da 82 [2] f1 ae [2] df 8c [2] cb 97 [2] c4 8d [2] da 90 [2] d8 91 [2] c3 97 [2] df 90 [2] c3 bf }

  condition:
    any of them
}