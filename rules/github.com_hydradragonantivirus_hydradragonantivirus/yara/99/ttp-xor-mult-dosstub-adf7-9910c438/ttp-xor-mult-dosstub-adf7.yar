rule TTP_XOR_MULT_DOSStub_adf7 {
  strings:
    $key_adf7 = { f9 9f [2] 8d 87 [2] ca 85 [2] 8d 94 [2] c3 98 [2] cf 92 [2] d8 99 [2] c3 d7 [2] fe }

  condition:
    any of them
}