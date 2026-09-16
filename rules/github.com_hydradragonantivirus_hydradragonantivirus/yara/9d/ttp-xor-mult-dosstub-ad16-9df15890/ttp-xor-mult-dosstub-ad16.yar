rule TTP_XOR_MULT_DOSStub_ad16 {
  strings:
    $key_ad16 = { f9 7e [2] 8d 66 [2] ca 64 [2] 8d 75 [2] c3 79 [2] cf 73 [2] d8 78 [2] c3 36 [2] fe }

  condition:
    any of them
}