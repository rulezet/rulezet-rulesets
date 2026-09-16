rule TTP_XOR_MULT_DOSStub_e9b5 {
  strings:
    $key_e9b5 = { bd dd [2] c9 c5 [2] 8e c7 [2] c9 d6 [2] 87 da [2] 8b d0 [2] 9c db [2] 87 95 [2] ba }

  condition:
    any of them
}