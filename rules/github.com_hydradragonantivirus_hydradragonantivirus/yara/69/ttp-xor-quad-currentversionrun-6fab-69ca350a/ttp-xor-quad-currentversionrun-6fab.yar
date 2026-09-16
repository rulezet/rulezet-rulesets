rule TTP_XOR_QUAD_CurrentVersionRun_6fab {
  strings:
    $key_6fab = { 3c c4 [2] 18 ca [2] 33 e6 [2] 1d c4 [2] 09 df [2] 06 c5 [2] 18 d8 [2] 1a d9 [2] 01 df [2] 1d d8 [2] 01 f7 }

  condition:
    any of them
}