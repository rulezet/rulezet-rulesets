rule TTP_XOR_QUAD_CurrentVersionRun_cbaa {
  strings:
    $key_cbaa = { 98 c5 [2] bc cb [2] 97 e7 [2] b9 c5 [2] ad de [2] a2 c4 [2] bc d9 [2] be d8 [2] a5 de [2] b9 d9 [2] a5 f6 }

  condition:
    any of them
}