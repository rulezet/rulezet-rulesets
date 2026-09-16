rule TTP_XOR_MULT_DOSStub_ad62 {
  strings:
    $key_ad62 = { f9 0a [2] 8d 12 [2] ca 10 [2] 8d 01 [2] c3 0d [2] cf 07 [2] d8 0c [2] c3 42 [2] fe }

  condition:
    any of them
}