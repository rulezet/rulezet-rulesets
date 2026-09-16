rule TTP_XOR_MULT_DOSStub_ad77 {
  strings:
    $key_ad77 = { f9 1f [2] 8d 07 [2] ca 05 [2] 8d 14 [2] c3 18 [2] cf 12 [2] d8 19 [2] c3 57 [2] fe }

  condition:
    any of them
}