rule TTP_XOR_QUAD_CurrentVersionRun_3ebe {
  strings:
    $key_3ebe = { 6d d1 [2] 49 df [2] 62 f3 [2] 4c d1 [2] 58 ca [2] 57 d0 [2] 49 cd [2] 4b cc [2] 50 ca [2] 4c cd [2] 50 e2 }

  condition:
    any of them
}