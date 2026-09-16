rule TTP_XOR_MULT_DOSStub_ad5f {
  strings:
    $key_ad5f = { f9 37 [2] 8d 2f [2] ca 2d [2] 8d 3c [2] c3 30 [2] cf 3a [2] d8 31 [2] c3 7f [2] fe }

  condition:
    any of them
}