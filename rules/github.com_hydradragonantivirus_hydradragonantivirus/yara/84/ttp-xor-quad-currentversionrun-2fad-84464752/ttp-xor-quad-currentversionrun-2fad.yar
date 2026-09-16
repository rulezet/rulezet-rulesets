rule TTP_XOR_QUAD_CurrentVersionRun_2fad {
  strings:
    $key_2fad = { 7c c2 [2] 58 cc [2] 73 e0 [2] 5d c2 [2] 49 d9 [2] 46 c3 [2] 58 de [2] 5a df [2] 41 d9 [2] 5d de [2] 41 f1 }

  condition:
    any of them
}