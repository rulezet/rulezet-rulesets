rule TTP_XOR_MULT_DOSStub_ad33 {
  strings:
    $key_ad33 = { f9 5b [2] 8d 43 [2] ca 41 [2] 8d 50 [2] c3 5c [2] cf 56 [2] d8 5d [2] c3 13 [2] fe }

  condition:
    any of them
}