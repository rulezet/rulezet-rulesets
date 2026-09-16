rule TTP_XOR_QUAD_CurrentVersionRun_cba5 {
  strings:
    $key_cba5 = { 98 ca [2] bc c4 [2] 97 e8 [2] b9 ca [2] ad d1 [2] a2 cb [2] bc d6 [2] be d7 [2] a5 d1 [2] b9 d6 [2] a5 f9 }

  condition:
    any of them
}