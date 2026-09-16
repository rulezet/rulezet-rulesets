rule TTP_XOR_QUAD_CurrentVersionRun_5fab {
  strings:
    $key_5fab = { 0c c4 [2] 28 ca [2] 03 e6 [2] 2d c4 [2] 39 df [2] 36 c5 [2] 28 d8 [2] 2a d9 [2] 31 df [2] 2d d8 [2] 31 f7 }

  condition:
    any of them
}