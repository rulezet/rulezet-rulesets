rule TTP_XOR_QUAD_CurrentVersionRun_17ba {
  strings:
    $key_17ba = { 44 d5 [2] 60 db [2] 4b f7 [2] 65 d5 [2] 71 ce [2] 7e d4 [2] 60 c9 [2] 62 c8 [2] 79 ce [2] 65 c9 [2] 79 e6 }

  condition:
    any of them
}