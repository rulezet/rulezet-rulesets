rule TTP_XOR_QUAD_CurrentVersionRun_7bbe {
  strings:
    $key_7bbe = { 28 d1 [2] 0c df [2] 27 f3 [2] 09 d1 [2] 1d ca [2] 12 d0 [2] 0c cd [2] 0e cc [2] 15 ca [2] 09 cd [2] 15 e2 }

  condition:
    any of them
}