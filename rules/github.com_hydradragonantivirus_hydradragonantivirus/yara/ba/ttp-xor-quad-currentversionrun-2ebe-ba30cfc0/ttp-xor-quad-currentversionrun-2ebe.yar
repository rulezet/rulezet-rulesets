rule TTP_XOR_QUAD_CurrentVersionRun_2ebe {
  strings:
    $key_2ebe = { 7d d1 [2] 59 df [2] 72 f3 [2] 5c d1 [2] 48 ca [2] 47 d0 [2] 59 cd [2] 5b cc [2] 40 ca [2] 5c cd [2] 40 e2 }

  condition:
    any of them
}