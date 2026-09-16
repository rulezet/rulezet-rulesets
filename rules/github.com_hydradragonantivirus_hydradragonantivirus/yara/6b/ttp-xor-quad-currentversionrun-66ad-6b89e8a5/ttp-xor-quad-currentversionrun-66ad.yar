rule TTP_XOR_QUAD_CurrentVersionRun_66ad {
  strings:
    $key_66ad = { 35 c2 [2] 11 cc [2] 3a e0 [2] 14 c2 [2] 00 d9 [2] 0f c3 [2] 11 de [2] 13 df [2] 08 d9 [2] 14 de [2] 08 f1 }

  condition:
    any of them
}