rule TTP_XOR_QUAD_CurrentVersionRun_e0ab {
  strings:
    $key_e0ab = { b3 c4 [2] 97 ca [2] bc e6 [2] 92 c4 [2] 86 df [2] 89 c5 [2] 97 d8 [2] 95 d9 [2] 8e df [2] 92 d8 [2] 8e f7 }

  condition:
    any of them
}