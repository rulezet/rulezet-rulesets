rule TTP_XOR_QUAD_CurrentVersionRun_bca6 {
  strings:
    $key_bca6 = { ef c9 [2] cb c7 [2] e0 eb [2] ce c9 [2] da d2 [2] d5 c8 [2] cb d5 [2] c9 d4 [2] d2 d2 [2] ce d5 [2] d2 fa }

  condition:
    any of them
}