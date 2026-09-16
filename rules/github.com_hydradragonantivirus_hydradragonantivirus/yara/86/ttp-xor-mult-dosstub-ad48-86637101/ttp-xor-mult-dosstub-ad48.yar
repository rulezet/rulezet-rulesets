rule TTP_XOR_MULT_DOSStub_ad48 {
  strings:
    $key_ad48 = { f9 20 [2] 8d 38 [2] ca 3a [2] 8d 2b [2] c3 27 [2] cf 2d [2] d8 26 [2] c3 68 [2] fe }

  condition:
    any of them
}