rule TTP_XOR_MULT_DOSStub_ad78 {
  strings:
    $key_ad78 = { f9 10 [2] 8d 08 [2] ca 0a [2] 8d 1b [2] c3 17 [2] cf 1d [2] d8 16 [2] c3 58 [2] fe }

  condition:
    any of them
}