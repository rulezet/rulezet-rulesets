rule TTP_XOR_QUAD_CurrentVersionRun_3bab {
  strings:
    $key_3bab = { 68 c4 [2] 4c ca [2] 67 e6 [2] 49 c4 [2] 5d df [2] 52 c5 [2] 4c d8 [2] 4e d9 [2] 55 df [2] 49 d8 [2] 55 f7 }

  condition:
    any of them
}