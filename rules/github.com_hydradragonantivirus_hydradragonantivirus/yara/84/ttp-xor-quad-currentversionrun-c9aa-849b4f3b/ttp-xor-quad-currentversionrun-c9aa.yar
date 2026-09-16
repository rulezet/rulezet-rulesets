rule TTP_XOR_QUAD_CurrentVersionRun_c9aa {
  strings:
    $key_c9aa = { 9a c5 [2] be cb [2] 95 e7 [2] bb c5 [2] af de [2] a0 c4 [2] be d9 [2] bc d8 [2] a7 de [2] bb d9 [2] a7 f6 }

  condition:
    any of them
}