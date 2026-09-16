rule TTP_XOR_QUAD_CurrentVersionRun_bcb6 {
  strings:
    $key_bcb6 = { ef d9 [2] cb d7 [2] e0 fb [2] ce d9 [2] da c2 [2] d5 d8 [2] cb c5 [2] c9 c4 [2] d2 c2 [2] ce c5 [2] d2 ea }

  condition:
    any of them
}