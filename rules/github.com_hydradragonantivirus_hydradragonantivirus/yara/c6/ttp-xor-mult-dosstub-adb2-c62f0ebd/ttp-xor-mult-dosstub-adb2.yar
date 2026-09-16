rule TTP_XOR_MULT_DOSStub_adb2 {
  strings:
    $key_adb2 = { f9 da [2] 8d c2 [2] ca c0 [2] 8d d1 [2] c3 dd [2] cf d7 [2] d8 dc [2] c3 92 [2] fe }

  condition:
    any of them
}