rule TTP_XOR_QUAD_CurrentVersionRun_7bad {
  strings:
    $key_7bad = { 28 c2 [2] 0c cc [2] 27 e0 [2] 09 c2 [2] 1d d9 [2] 12 c3 [2] 0c de [2] 0e df [2] 15 d9 [2] 09 de [2] 15 f1 }

  condition:
    any of them
}