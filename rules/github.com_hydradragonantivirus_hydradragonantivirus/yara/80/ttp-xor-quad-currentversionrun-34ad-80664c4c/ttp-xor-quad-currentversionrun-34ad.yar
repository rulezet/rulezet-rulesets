rule TTP_XOR_QUAD_CurrentVersionRun_34ad {
  strings:
    $key_34ad = { 67 c2 [2] 43 cc [2] 68 e0 [2] 46 c2 [2] 52 d9 [2] 5d c3 [2] 43 de [2] 41 df [2] 5a d9 [2] 46 de [2] 5a f1 }

  condition:
    any of them
}