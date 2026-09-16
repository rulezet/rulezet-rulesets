rule TTP_XOR_MULT_DOSStub_ad65 {
  strings:
    $key_ad65 = { f9 0d [2] 8d 15 [2] ca 17 [2] 8d 06 [2] c3 0a [2] cf 00 [2] d8 0b [2] c3 45 [2] fe }

  condition:
    any of them
}