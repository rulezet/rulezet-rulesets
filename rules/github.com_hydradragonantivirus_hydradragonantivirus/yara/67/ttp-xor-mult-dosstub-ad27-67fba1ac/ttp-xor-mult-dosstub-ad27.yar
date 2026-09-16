rule TTP_XOR_MULT_DOSStub_ad27 {
  strings:
    $key_ad27 = { f9 4f [2] 8d 57 [2] ca 55 [2] 8d 44 [2] c3 48 [2] cf 42 [2] d8 49 [2] c3 07 [2] fe }

  condition:
    any of them
}