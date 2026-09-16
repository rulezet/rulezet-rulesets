rule TTP_XOR_QUAD_CurrentVersionRun_54ad {
  strings:
    $key_54ad = { 07 c2 [2] 23 cc [2] 08 e0 [2] 26 c2 [2] 32 d9 [2] 3d c3 [2] 23 de [2] 21 df [2] 3a d9 [2] 26 de [2] 3a f1 }

  condition:
    any of them
}