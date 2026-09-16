rule TTP_XOR_QUAD_CurrentVersionRun_4fad {
  strings:
    $key_4fad = { 1c c2 [2] 38 cc [2] 13 e0 [2] 3d c2 [2] 29 d9 [2] 26 c3 [2] 38 de [2] 3a df [2] 21 d9 [2] 3d de [2] 21 f1 }

  condition:
    any of them
}