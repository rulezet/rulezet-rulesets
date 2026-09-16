rule TTP_XOR_MULT_DOSStub_ad14 {
  strings:
    $key_ad14 = { f9 7c [2] 8d 64 [2] ca 66 [2] 8d 77 [2] c3 7b [2] cf 71 [2] d8 7a [2] c3 34 [2] fe }

  condition:
    any of them
}