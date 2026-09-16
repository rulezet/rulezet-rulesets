rule TTP_XOR_MULT_DOSStub_ad08 {
  strings:
    $key_ad08 = { f9 60 [2] 8d 78 [2] ca 7a [2] 8d 6b [2] c3 67 [2] cf 6d [2] d8 66 [2] c3 28 [2] fe }

  condition:
    any of them
}