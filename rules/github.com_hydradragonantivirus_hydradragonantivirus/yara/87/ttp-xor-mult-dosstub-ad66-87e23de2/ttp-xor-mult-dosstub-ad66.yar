rule TTP_XOR_MULT_DOSStub_ad66 {
  strings:
    $key_ad66 = { f9 0e [2] 8d 16 [2] ca 14 [2] 8d 05 [2] c3 09 [2] cf 03 [2] d8 08 [2] c3 46 [2] fe }

  condition:
    any of them
}