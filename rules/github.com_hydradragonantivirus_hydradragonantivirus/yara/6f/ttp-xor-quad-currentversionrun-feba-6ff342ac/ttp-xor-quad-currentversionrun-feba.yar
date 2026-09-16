rule TTP_XOR_QUAD_CurrentVersionRun_feba {
  strings:
    $key_feba = { ad d5 [2] 89 db [2] a2 f7 [2] 8c d5 [2] 98 ce [2] 97 d4 [2] 89 c9 [2] 8b c8 [2] 90 ce [2] 8c c9 [2] 90 e6 }

  condition:
    any of them
}