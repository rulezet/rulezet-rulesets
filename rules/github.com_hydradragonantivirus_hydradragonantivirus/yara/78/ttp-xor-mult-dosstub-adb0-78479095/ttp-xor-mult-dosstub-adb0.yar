rule TTP_XOR_MULT_DOSStub_adb0 {
  strings:
    $key_adb0 = { f9 d8 [2] 8d c0 [2] ca c2 [2] 8d d3 [2] c3 df [2] cf d5 [2] d8 de [2] c3 90 [2] fe }

  condition:
    any of them
}