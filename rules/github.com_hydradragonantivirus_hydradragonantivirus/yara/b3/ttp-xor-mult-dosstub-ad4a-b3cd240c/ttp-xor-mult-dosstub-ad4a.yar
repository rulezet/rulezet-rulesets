rule TTP_XOR_MULT_DOSStub_ad4a {
  strings:
    $key_ad4a = { f9 22 [2] 8d 3a [2] ca 38 [2] 8d 29 [2] c3 25 [2] cf 2f [2] d8 24 [2] c3 6a [2] fe }

  condition:
    any of them
}