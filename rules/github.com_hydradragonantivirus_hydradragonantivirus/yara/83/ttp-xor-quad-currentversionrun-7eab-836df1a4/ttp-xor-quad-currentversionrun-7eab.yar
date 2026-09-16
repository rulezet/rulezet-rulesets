rule TTP_XOR_QUAD_CurrentVersionRun_7eab {
  strings:
    $key_7eab = { 2d c4 [2] 09 ca [2] 22 e6 [2] 0c c4 [2] 18 df [2] 17 c5 [2] 09 d8 [2] 0b d9 [2] 10 df [2] 0c d8 [2] 10 f7 }

  condition:
    any of them
}