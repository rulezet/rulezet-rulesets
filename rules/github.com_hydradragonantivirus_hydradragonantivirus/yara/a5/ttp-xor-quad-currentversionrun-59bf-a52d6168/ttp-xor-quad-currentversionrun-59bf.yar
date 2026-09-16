rule TTP_XOR_QUAD_CurrentVersionRun_59bf {
  strings:
    $key_59bf = { 0a d0 [2] 2e de [2] 05 f2 [2] 2b d0 [2] 3f cb [2] 30 d1 [2] 2e cc [2] 2c cd [2] 37 cb [2] 2b cc [2] 37 e3 }

  condition:
    any of them
}