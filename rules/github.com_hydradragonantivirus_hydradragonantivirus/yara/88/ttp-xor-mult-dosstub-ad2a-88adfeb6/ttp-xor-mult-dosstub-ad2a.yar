rule TTP_XOR_MULT_DOSStub_ad2a {
  strings:
    $key_ad2a = { f9 42 [2] 8d 5a [2] ca 58 [2] 8d 49 [2] c3 45 [2] cf 4f [2] d8 44 [2] c3 0a [2] fe }

  condition:
    any of them
}