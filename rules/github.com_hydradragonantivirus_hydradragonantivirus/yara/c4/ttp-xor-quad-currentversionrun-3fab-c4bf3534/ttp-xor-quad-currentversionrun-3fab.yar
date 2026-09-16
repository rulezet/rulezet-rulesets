rule TTP_XOR_QUAD_CurrentVersionRun_3fab {
  strings:
    $key_3fab = { 6c c4 [2] 48 ca [2] 63 e6 [2] 4d c4 [2] 59 df [2] 56 c5 [2] 48 d8 [2] 4a d9 [2] 51 df [2] 4d d8 [2] 51 f7 }

  condition:
    any of them
}