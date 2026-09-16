rule TTP_XOR_MULT_DOSStub_ad1a {
  strings:
    $key_ad1a = { f9 72 [2] 8d 6a [2] ca 68 [2] 8d 79 [2] c3 75 [2] cf 7f [2] d8 74 [2] c3 3a [2] fe }

  condition:
    any of them
}