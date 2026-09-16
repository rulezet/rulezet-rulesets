rule TTP_XOR_QUAD_CurrentVersionRun_3eab {
  strings:
    $key_3eab = { 6d c4 [2] 49 ca [2] 62 e6 [2] 4c c4 [2] 58 df [2] 57 c5 [2] 49 d8 [2] 4b d9 [2] 50 df [2] 4c d8 [2] 50 f7 }

  condition:
    any of them
}