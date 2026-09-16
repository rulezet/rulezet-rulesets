rule TTP_XOR_QUAD_CurrentVersionRun_46ad {
  strings:
    $key_46ad = { 15 c2 [2] 31 cc [2] 1a e0 [2] 34 c2 [2] 20 d9 [2] 2f c3 [2] 31 de [2] 33 df [2] 28 d9 [2] 34 de [2] 28 f1 }

  condition:
    any of them
}