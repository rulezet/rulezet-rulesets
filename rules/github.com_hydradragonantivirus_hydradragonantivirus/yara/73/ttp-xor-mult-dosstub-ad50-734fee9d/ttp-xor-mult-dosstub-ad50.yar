rule TTP_XOR_MULT_DOSStub_ad50 {
  strings:
    $key_ad50 = { f9 38 [2] 8d 20 [2] ca 22 [2] 8d 33 [2] c3 3f [2] cf 35 [2] d8 3e [2] c3 70 [2] fe }

  condition:
    any of them
}