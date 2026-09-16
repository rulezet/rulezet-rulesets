rule TTP_XOR_QUAD_CurrentVersionRun_3ead {
  strings:
    $key_3ead = { 6d c2 [2] 49 cc [2] 62 e0 [2] 4c c2 [2] 58 d9 [2] 57 c3 [2] 49 de [2] 4b df [2] 50 d9 [2] 4c de [2] 50 f1 }

  condition:
    any of them
}