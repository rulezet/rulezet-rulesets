rule TTP_XOR_MULT_DOSStub_ad39 {
  strings:
    $key_ad39 = { f9 51 [2] 8d 49 [2] ca 4b [2] 8d 5a [2] c3 56 [2] cf 5c [2] d8 57 [2] c3 19 [2] fe }

  condition:
    any of them
}