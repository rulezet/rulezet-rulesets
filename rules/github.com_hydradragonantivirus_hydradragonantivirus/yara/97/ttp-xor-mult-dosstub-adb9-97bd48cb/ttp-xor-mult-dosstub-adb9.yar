rule TTP_XOR_MULT_DOSStub_adb9 {
  strings:
    $key_adb9 = { f9 d1 [2] 8d c9 [2] ca cb [2] 8d da [2] c3 d6 [2] cf dc [2] d8 d7 [2] c3 99 [2] fe }

  condition:
    any of them
}