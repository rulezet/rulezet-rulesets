rule TTP_XOR_QUAD_CurrentVersionRun_febe {
  strings:
    $key_febe = { ad d1 [2] 89 df [2] a2 f3 [2] 8c d1 [2] 98 ca [2] 97 d0 [2] 89 cd [2] 8b cc [2] 90 ca [2] 8c cd [2] 90 e2 }

  condition:
    any of them
}