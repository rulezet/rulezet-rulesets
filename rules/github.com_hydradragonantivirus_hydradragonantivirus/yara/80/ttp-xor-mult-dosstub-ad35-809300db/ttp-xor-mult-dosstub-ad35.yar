rule TTP_XOR_MULT_DOSStub_ad35 {
  strings:
    $key_ad35 = { f9 5d [2] 8d 45 [2] ca 47 [2] 8d 56 [2] c3 5a [2] cf 50 [2] d8 5b [2] c3 15 [2] fe }

  condition:
    any of them
}