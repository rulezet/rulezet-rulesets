rule TTP_XOR_QUAD_CurrentVersionRun_26ad {
  strings:
    $key_26ad = { 75 c2 [2] 51 cc [2] 7a e0 [2] 54 c2 [2] 40 d9 [2] 4f c3 [2] 51 de [2] 53 df [2] 48 d9 [2] 54 de [2] 48 f1 }

  condition:
    any of them
}