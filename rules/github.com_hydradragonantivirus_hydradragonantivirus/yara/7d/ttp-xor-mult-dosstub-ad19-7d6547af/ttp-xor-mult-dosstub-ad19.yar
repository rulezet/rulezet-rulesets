rule TTP_XOR_MULT_DOSStub_ad19 {
  strings:
    $key_ad19 = { f9 71 [2] 8d 69 [2] ca 6b [2] 8d 7a [2] c3 76 [2] cf 7c [2] d8 77 [2] c3 39 [2] fe }

  condition:
    any of them
}