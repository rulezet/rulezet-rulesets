rule TTP_XOR_QUAD_CurrentVersionRun_65ad {
  strings:
    $key_65ad = { 36 c2 [2] 12 cc [2] 39 e0 [2] 17 c2 [2] 03 d9 [2] 0c c3 [2] 12 de [2] 10 df [2] 0b d9 [2] 17 de [2] 0b f1 }

  condition:
    any of them
}