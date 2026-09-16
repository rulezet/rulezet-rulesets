rule TTP_XOR_MULT_DOSStub_adb4 {
  strings:
    $key_adb4 = { f9 dc [2] 8d c4 [2] ca c6 [2] 8d d7 [2] c3 db [2] cf d1 [2] d8 da [2] c3 94 [2] fe }

  condition:
    any of them
}