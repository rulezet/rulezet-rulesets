rule TTP_XOR_MULT_DOSStub_ad46 {
  strings:
    $key_ad46 = { f9 2e [2] 8d 36 [2] ca 34 [2] 8d 25 [2] c3 29 [2] cf 23 [2] d8 28 [2] c3 66 [2] fe }

  condition:
    any of them
}