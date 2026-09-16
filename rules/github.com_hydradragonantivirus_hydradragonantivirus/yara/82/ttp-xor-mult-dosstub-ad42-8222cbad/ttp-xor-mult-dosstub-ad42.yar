rule TTP_XOR_MULT_DOSStub_ad42 {
  strings:
    $key_ad42 = { f9 2a [2] 8d 32 [2] ca 30 [2] 8d 21 [2] c3 2d [2] cf 27 [2] d8 2c [2] c3 62 [2] fe }

  condition:
    any of them
}