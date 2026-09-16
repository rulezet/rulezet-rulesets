rule TTP_XOR_MULT_DOSStub_e9b4 {
  strings:
    $key_e9b4 = { bd dc [2] c9 c4 [2] 8e c6 [2] c9 d7 [2] 87 db [2] 8b d1 [2] 9c da [2] 87 94 [2] ba }

  condition:
    any of them
}