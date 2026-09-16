rule TTP_XOR_QUAD_CurrentVersionRun_5eab {
  strings:
    $key_5eab = { 0d c4 [2] 29 ca [2] 02 e6 [2] 2c c4 [2] 38 df [2] 37 c5 [2] 29 d8 [2] 2b d9 [2] 30 df [2] 2c d8 [2] 30 f7 }

  condition:
    any of them
}