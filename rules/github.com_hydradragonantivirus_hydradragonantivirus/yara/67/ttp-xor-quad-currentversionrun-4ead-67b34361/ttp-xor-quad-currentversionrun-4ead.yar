rule TTP_XOR_QUAD_CurrentVersionRun_4ead {
  strings:
    $key_4ead = { 1d c2 [2] 39 cc [2] 12 e0 [2] 3c c2 [2] 28 d9 [2] 27 c3 [2] 39 de [2] 3b df [2] 20 d9 [2] 3c de [2] 20 f1 }

  condition:
    any of them
}