rule TTP_XOR_QUAD_CurrentVersionRun_62ad {
  strings:
    $key_62ad = { 31 c2 [2] 15 cc [2] 3e e0 [2] 10 c2 [2] 04 d9 [2] 0b c3 [2] 15 de [2] 17 df [2] 0c d9 [2] 10 de [2] 0c f1 }

  condition:
    any of them
}