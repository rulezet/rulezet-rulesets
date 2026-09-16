rule TTP_XOR_MULT_DOSStub_ad5b {
  strings:
    $key_ad5b = { f9 33 [2] 8d 2b [2] ca 29 [2] 8d 38 [2] c3 34 [2] cf 3e [2] d8 35 [2] c3 7b [2] fe }

  condition:
    any of them
}