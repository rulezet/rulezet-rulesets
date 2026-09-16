rule TTP_XOR_MULT_DOSStub_adb7 {
  strings:
    $key_adb7 = { f9 df [2] 8d c7 [2] ca c5 [2] 8d d4 [2] c3 d8 [2] cf d2 [2] d8 d9 [2] c3 97 [2] fe }

  condition:
    any of them
}