rule TTP_XOR_QUAD_CurrentVersionRun_ad8a {
  strings:
    $key_ad8a = { fe e5 [2] da eb [2] f1 c7 [2] df e5 [2] cb fe [2] c4 e4 [2] da f9 [2] d8 f8 [2] c3 fe [2] df f9 [2] c3 d6 }

  condition:
    any of them
}