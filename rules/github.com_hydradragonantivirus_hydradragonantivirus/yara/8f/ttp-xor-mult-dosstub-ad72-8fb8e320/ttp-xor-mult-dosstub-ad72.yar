rule TTP_XOR_MULT_DOSStub_ad72 {
  strings:
    $key_ad72 = { f9 1a [2] 8d 02 [2] ca 00 [2] 8d 11 [2] c3 1d [2] cf 17 [2] d8 1c [2] c3 52 [2] fe }

  condition:
    any of them
}