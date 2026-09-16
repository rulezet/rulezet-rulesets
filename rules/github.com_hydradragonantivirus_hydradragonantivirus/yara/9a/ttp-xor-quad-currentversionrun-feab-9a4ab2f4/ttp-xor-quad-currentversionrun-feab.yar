rule TTP_XOR_QUAD_CurrentVersionRun_feab {
  strings:
    $key_feab = { ad c4 [2] 89 ca [2] a2 e6 [2] 8c c4 [2] 98 df [2] 97 c5 [2] 89 d8 [2] 8b d9 [2] 90 df [2] 8c d8 [2] 90 f7 }

  condition:
    any of them
}