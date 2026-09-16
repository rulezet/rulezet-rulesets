rule TTP_XOR_MULT_DOSStub_ad5a {
  strings:
    $key_ad5a = { f9 32 [2] 8d 2a [2] ca 28 [2] 8d 39 [2] c3 35 [2] cf 3f [2] d8 34 [2] c3 7a [2] fe }

  condition:
    any of them
}