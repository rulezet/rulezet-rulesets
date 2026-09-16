rule TTP_XOR_MULT_DOSStub_ad31 {
  strings:
    $key_ad31 = { f9 59 [2] 8d 41 [2] ca 43 [2] 8d 52 [2] c3 5e [2] cf 54 [2] d8 5f [2] c3 11 [2] fe }

  condition:
    any of them
}