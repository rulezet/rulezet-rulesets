rule TTP_XOR_QUAD_CurrentVersionRun_7ebe {
  strings:
    $key_7ebe = { 2d d1 [2] 09 df [2] 22 f3 [2] 0c d1 [2] 18 ca [2] 17 d0 [2] 09 cd [2] 0b cc [2] 10 ca [2] 0c cd [2] 10 e2 }

  condition:
    any of them
}