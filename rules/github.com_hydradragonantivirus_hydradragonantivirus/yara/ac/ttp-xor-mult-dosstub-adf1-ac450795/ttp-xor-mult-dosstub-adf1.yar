rule TTP_XOR_MULT_DOSStub_adf1 {
  strings:
    $key_adf1 = { f9 99 [2] 8d 81 [2] ca 83 [2] 8d 92 [2] c3 9e [2] cf 94 [2] d8 9f [2] c3 d1 [2] fe }

  condition:
    any of them
}