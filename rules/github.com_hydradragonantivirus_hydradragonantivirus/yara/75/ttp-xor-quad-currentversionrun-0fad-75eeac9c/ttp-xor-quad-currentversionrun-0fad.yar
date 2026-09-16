rule TTP_XOR_QUAD_CurrentVersionRun_0fad {
  strings:
    $key_0fad = { 5c c2 [2] 78 cc [2] 53 e0 [2] 7d c2 [2] 69 d9 [2] 66 c3 [2] 78 de [2] 7a df [2] 61 d9 [2] 7d de [2] 61 f1 }

  condition:
    any of them
}