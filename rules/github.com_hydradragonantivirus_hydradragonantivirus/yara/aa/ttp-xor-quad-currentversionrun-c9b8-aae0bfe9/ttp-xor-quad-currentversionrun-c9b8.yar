rule TTP_XOR_QUAD_CurrentVersionRun_c9b8 {
  strings:
    $key_c9b8 = { 9a d7 [2] be d9 [2] 95 f5 [2] bb d7 [2] af cc [2] a0 d6 [2] be cb [2] bc ca [2] a7 cc [2] bb cb [2] a7 e4 }

  condition:
    any of them
}