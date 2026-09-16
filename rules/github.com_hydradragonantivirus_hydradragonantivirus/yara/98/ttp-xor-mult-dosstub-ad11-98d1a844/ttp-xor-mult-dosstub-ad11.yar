rule TTP_XOR_MULT_DOSStub_ad11 {
  strings:
    $key_ad11 = { f9 79 [2] 8d 61 [2] ca 63 [2] 8d 72 [2] c3 7e [2] cf 74 [2] d8 7f [2] c3 31 [2] fe }

  condition:
    any of them
}