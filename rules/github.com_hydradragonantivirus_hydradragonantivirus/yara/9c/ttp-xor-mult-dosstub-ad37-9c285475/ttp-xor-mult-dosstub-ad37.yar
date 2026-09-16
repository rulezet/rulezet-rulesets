rule TTP_XOR_MULT_DOSStub_ad37 {
  strings:
    $key_ad37 = { f9 5f [2] 8d 47 [2] ca 45 [2] 8d 54 [2] c3 58 [2] cf 52 [2] d8 59 [2] c3 17 [2] fe }

  condition:
    any of them
}