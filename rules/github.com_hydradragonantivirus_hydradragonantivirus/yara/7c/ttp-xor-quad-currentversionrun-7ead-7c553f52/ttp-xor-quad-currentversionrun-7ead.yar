rule TTP_XOR_QUAD_CurrentVersionRun_7ead {
  strings:
    $key_7ead = { 2d c2 [2] 09 cc [2] 22 e0 [2] 0c c2 [2] 18 d9 [2] 17 c3 [2] 09 de [2] 0b df [2] 10 d9 [2] 0c de [2] 10 f1 }

  condition:
    any of them
}