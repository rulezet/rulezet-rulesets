rule TTP_XOR_QUAD_CurrentVersionRun_fbbe {
  strings:
    $key_fbbe = { a8 d1 [2] 8c df [2] a7 f3 [2] 89 d1 [2] 9d ca [2] 92 d0 [2] 8c cd [2] 8e cc [2] 95 ca [2] 89 cd [2] 95 e2 }

  condition:
    any of them
}