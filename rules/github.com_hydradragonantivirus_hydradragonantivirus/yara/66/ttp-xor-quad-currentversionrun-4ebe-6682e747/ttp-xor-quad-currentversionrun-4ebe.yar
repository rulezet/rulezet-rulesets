rule TTP_XOR_QUAD_CurrentVersionRun_4ebe {
  strings:
    $key_4ebe = { 1d d1 [2] 39 df [2] 12 f3 [2] 3c d1 [2] 28 ca [2] 27 d0 [2] 39 cd [2] 3b cc [2] 20 ca [2] 3c cd [2] 20 e2 }

  condition:
    any of them
}