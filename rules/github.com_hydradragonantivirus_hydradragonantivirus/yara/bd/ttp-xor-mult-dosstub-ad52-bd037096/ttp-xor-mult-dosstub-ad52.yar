rule TTP_XOR_MULT_DOSStub_ad52 {
  strings:
    $key_ad52 = { f9 3a [2] 8d 22 [2] ca 20 [2] 8d 31 [2] c3 3d [2] cf 37 [2] d8 3c [2] c3 72 [2] fe }

  condition:
    any of them
}