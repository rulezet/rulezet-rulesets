rule TTP_XOR_QUAD_CurrentVersionRun_2eab {
  strings:
    $key_2eab = { 7d c4 [2] 59 ca [2] 72 e6 [2] 5c c4 [2] 48 df [2] 47 c5 [2] 59 d8 [2] 5b d9 [2] 40 df [2] 5c d8 [2] 40 f7 }

  condition:
    any of them
}