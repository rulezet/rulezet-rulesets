rule TTP_XOR_MULT_DOSStub_ad18 {
  strings:
    $key_ad18 = { f9 70 [2] 8d 68 [2] ca 6a [2] 8d 7b [2] c3 77 [2] cf 7d [2] d8 76 [2] c3 38 [2] fe }

  condition:
    any of them
}