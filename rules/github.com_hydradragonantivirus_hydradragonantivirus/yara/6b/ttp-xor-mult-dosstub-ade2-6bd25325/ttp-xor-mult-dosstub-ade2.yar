rule TTP_XOR_MULT_DOSStub_ade2 {
  strings:
    $key_ade2 = { f9 8a [2] 8d 92 [2] ca 90 [2] 8d 81 [2] c3 8d [2] cf 87 [2] d8 8c [2] c3 c2 [2] fe }

  condition:
    any of them
}