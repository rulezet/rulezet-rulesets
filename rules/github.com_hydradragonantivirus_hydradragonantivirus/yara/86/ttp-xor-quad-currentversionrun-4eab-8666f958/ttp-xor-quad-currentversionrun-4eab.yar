rule TTP_XOR_QUAD_CurrentVersionRun_4eab {
  strings:
    $key_4eab = { 1d c4 [2] 39 ca [2] 12 e6 [2] 3c c4 [2] 28 df [2] 27 c5 [2] 39 d8 [2] 3b d9 [2] 20 df [2] 3c d8 [2] 20 f7 }

  condition:
    any of them
}