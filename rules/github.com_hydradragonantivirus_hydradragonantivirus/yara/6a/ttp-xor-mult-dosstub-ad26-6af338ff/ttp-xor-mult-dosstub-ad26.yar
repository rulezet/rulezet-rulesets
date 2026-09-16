rule TTP_XOR_MULT_DOSStub_ad26 {
  strings:
    $key_ad26 = { f9 4e [2] 8d 56 [2] ca 54 [2] 8d 45 [2] c3 49 [2] cf 43 [2] d8 48 [2] c3 06 [2] fe }

  condition:
    any of them
}