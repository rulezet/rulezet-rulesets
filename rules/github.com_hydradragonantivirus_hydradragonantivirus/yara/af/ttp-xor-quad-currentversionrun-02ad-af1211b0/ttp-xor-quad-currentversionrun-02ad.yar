rule TTP_XOR_QUAD_CurrentVersionRun_02ad {
  strings:
    $key_02ad = { 51 c2 [2] 75 cc [2] 5e e0 [2] 70 c2 [2] 64 d9 [2] 6b c3 [2] 75 de [2] 77 df [2] 6c d9 [2] 70 de [2] 6c f1 }

  condition:
    any of them
}