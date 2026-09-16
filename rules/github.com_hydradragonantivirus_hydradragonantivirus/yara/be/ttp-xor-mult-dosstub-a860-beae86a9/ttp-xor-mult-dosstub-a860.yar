rule TTP_XOR_MULT_DOSStub_a860 {
  strings:
    $key_a860 = { fc 08 [2] 88 10 [2] cf 12 [2] 88 03 [2] c6 0f [2] ca 05 [2] dd 0e [2] c6 40 [2] fb }

  condition:
    any of them
}