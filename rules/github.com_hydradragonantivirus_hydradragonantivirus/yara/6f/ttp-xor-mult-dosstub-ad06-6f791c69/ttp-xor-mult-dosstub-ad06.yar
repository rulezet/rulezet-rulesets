rule TTP_XOR_MULT_DOSStub_ad06 {
  strings:
    $key_ad06 = { f9 6e [2] 8d 76 [2] ca 74 [2] 8d 65 [2] c3 69 [2] cf 63 [2] d8 68 [2] c3 26 [2] fe }

  condition:
    any of them
}