rule TTP_XOR_QUAD_CurrentVersionRun_e9bf {
  strings:
    $key_e9bf = { ba d0 [2] 9e de [2] b5 f2 [2] 9b d0 [2] 8f cb [2] 80 d1 [2] 9e cc [2] 9c cd [2] 87 cb [2] 9b cc [2] 87 e3 }

  condition:
    any of them
}