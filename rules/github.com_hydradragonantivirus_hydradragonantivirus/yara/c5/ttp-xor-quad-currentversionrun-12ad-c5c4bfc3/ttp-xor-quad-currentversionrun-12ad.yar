rule TTP_XOR_QUAD_CurrentVersionRun_12ad {
  strings:
    $key_12ad = { 41 c2 [2] 65 cc [2] 4e e0 [2] 60 c2 [2] 74 d9 [2] 7b c3 [2] 65 de [2] 67 df [2] 7c d9 [2] 60 de [2] 7c f1 }

  condition:
    any of them
}