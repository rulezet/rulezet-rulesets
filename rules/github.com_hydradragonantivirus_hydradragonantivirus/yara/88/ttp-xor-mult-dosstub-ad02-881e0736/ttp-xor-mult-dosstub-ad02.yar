rule TTP_XOR_MULT_DOSStub_ad02 {
  strings:
    $key_ad02 = { f9 6a [2] 8d 72 [2] ca 70 [2] 8d 61 [2] c3 6d [2] cf 67 [2] d8 6c [2] c3 22 [2] fe }

  condition:
    any of them
}