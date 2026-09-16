rule TTP_XOR_MULT_DOSStub_ade4 {
  strings:
    $key_ade4 = { f9 8c [2] 8d 94 [2] ca 96 [2] 8d 87 [2] c3 8b [2] cf 81 [2] d8 8a [2] c3 c4 [2] fe }

  condition:
    any of them
}