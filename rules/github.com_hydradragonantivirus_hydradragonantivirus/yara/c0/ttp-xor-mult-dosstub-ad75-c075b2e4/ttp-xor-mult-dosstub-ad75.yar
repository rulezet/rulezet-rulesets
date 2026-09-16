rule TTP_XOR_MULT_DOSStub_ad75 {
  strings:
    $key_ad75 = { f9 1d [2] 8d 05 [2] ca 07 [2] 8d 16 [2] c3 1a [2] cf 10 [2] d8 1b [2] c3 55 [2] fe }

  condition:
    any of them
}