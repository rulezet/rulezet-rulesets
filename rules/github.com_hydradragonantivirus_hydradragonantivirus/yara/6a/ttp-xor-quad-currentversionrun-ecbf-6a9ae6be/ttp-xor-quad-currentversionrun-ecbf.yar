rule TTP_XOR_QUAD_CurrentVersionRun_ecbf {
  strings:
    $key_ecbf = { bf d0 [2] 9b de [2] b0 f2 [2] 9e d0 [2] 8a cb [2] 85 d1 [2] 9b cc [2] 99 cd [2] 82 cb [2] 9e cc [2] 82 e3 }

  condition:
    any of them
}