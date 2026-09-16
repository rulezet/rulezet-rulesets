rule TTP_XOR_MULT_DOSStub_ad10 {
  strings:
    $key_ad10 = { f9 78 [2] 8d 60 [2] ca 62 [2] 8d 73 [2] c3 7f [2] cf 75 [2] d8 7e [2] c3 30 [2] fe }

  condition:
    any of them
}