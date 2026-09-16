rule TTP_XOR_QUAD_CurrentVersionRun_b6aa {
  strings:
    $key_b6aa = { e5 c5 [2] c1 cb [2] ea e7 [2] c4 c5 [2] d0 de [2] df c4 [2] c1 d9 [2] c3 d8 [2] d8 de [2] c4 d9 [2] d8 f6 }

  condition:
    any of them
}