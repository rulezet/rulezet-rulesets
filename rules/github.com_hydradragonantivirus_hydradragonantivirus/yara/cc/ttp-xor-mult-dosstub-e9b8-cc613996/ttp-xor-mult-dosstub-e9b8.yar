rule TTP_XOR_MULT_DOSStub_e9b8 {
  strings:
    $key_e9b8 = { bd d0 [2] c9 c8 [2] 8e ca [2] c9 db [2] 87 d7 [2] 8b dd [2] 9c d6 [2] 87 98 [2] ba }

  condition:
    any of them
}