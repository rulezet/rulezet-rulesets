rule TTP_XOR_QUAD_CurrentVersionRun_aeba {
  strings:
    $key_aeba = { fd d5 [2] d9 db [2] f2 f7 [2] dc d5 [2] c8 ce [2] c7 d4 [2] d9 c9 [2] db c8 [2] c0 ce [2] dc c9 [2] c0 e6 }

  condition:
    any of them
}