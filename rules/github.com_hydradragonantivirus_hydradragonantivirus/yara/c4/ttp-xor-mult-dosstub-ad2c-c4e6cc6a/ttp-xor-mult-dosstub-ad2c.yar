rule TTP_XOR_MULT_DOSStub_ad2c {
  strings:
    $key_ad2c = { f9 44 [2] 8d 5c [2] ca 5e [2] 8d 4f [2] c3 43 [2] cf 49 [2] d8 42 [2] c3 0c [2] fe }

  condition:
    any of them
}