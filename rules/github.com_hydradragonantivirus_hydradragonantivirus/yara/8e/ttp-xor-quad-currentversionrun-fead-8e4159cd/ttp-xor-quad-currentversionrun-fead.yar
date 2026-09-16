rule TTP_XOR_QUAD_CurrentVersionRun_fead {
  strings:
    $key_fead = { ad c2 [2] 89 cc [2] a2 e0 [2] 8c c2 [2] 98 d9 [2] 97 c3 [2] 89 de [2] 8b df [2] 90 d9 [2] 8c de [2] 90 f1 }

  condition:
    any of them
}