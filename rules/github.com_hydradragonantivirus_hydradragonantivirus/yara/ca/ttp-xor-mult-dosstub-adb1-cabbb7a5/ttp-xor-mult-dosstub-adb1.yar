rule TTP_XOR_MULT_DOSStub_adb1 {
  strings:
    $key_adb1 = { f9 d9 [2] 8d c1 [2] ca c3 [2] 8d d2 [2] c3 de [2] cf d4 [2] d8 df [2] c3 91 [2] fe }

  condition:
    any of them
}