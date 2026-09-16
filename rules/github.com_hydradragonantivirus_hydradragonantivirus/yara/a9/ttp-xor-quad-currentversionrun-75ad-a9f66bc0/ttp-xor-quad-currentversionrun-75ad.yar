rule TTP_XOR_QUAD_CurrentVersionRun_75ad {
  strings:
    $key_75ad = { 26 c2 [2] 02 cc [2] 29 e0 [2] 07 c2 [2] 13 d9 [2] 1c c3 [2] 02 de [2] 00 df [2] 1b d9 [2] 07 de [2] 1b f1 }

  condition:
    any of them
}