rule TTP_XOR_QUAD_CurrentVersionRun_e0a5 {
  strings:
    $key_e0a5 = { b3 ca [2] 97 c4 [2] bc e8 [2] 92 ca [2] 86 d1 [2] 89 cb [2] 97 d6 [2] 95 d7 [2] 8e d1 [2] 92 d6 [2] 8e f9 }

  condition:
    any of them
}