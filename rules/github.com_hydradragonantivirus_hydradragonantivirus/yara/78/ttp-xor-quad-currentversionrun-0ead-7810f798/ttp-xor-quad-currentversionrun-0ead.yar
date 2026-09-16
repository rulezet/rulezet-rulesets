rule TTP_XOR_QUAD_CurrentVersionRun_0ead {
  strings:
    $key_0ead = { 5d c2 [2] 79 cc [2] 52 e0 [2] 7c c2 [2] 68 d9 [2] 67 c3 [2] 79 de [2] 7b df [2] 60 d9 [2] 7c de [2] 60 f1 }

  condition:
    any of them
}